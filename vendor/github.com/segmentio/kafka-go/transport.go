package kafka

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/segmentio/kafka-go/protocol"
	"github.com/segmentio/kafka-go/protocol/apiversions"
	"github.com/segmentio/kafka-go/protocol/createtopics"
	"github.com/segmentio/kafka-go/protocol/findcoordinator"
	meta "github.com/segmentio/kafka-go/protocol/metadata"
	"github.com/segmentio/kafka-go/protocol/saslauthenticate"
	"github.com/segmentio/kafka-go/protocol/saslhandshake"
	"github.com/segmentio/kafka-go/sasl"
)

// Request is an interface implemented by types that represent messages sent
// from kafka clients to brokers.
type Request = protocol.Message

// Response is an interface implemented by types that represent messages sent
// from kafka brokers in response to client requests.
type Response = protocol.Message

// RoundTripper is an interface implemented by types which support interacting
// with kafka brokers.
type RoundTripper interface {
	// RoundTrip sends a request to a kafka broker and returns the response that
	// was received, or a non-nil error.
	//
	// The context passed as first argument can be used to asynchronnously abort
	// the call if needed.
	RoundTrip(context.Context, net.Addr, Request) (Response, error)
}

// Transport is an implementation of the RoundTripper interface.
//
// Transport values manage a pool of connections and automatically discovers the
// clusters layout to route requests to the appropriate brokers.
//
// Transport values are safe to use concurrently from multiple goroutines.
//
// Note: The intent is for the Transport to become the underlying layer of the
// kafka.Reader and kafka.Writer types.
type Transport struct {
	// A function used to establish connections to the kafka cluster.
	Dial func(context.Context, string, string) (net.Conn, error)

	// Time limit set for establishing connections to the kafka cluster. This
	// limit includes all round trips done to establish the connections (TLS
	// hadbhaske, SASL negotiation, etc...).
	//
	// Defaults to 5s.
	DialTimeout time.Duration

	// Maximum amount of time that connections will remain open and unused.
	// The transport will manage to automatically close connections that have
	// been idle for too long, and re-open them on demand when the transport is
	// used again.
	//
	// Defaults to 30s.
	IdleTimeout time.Duration

	// TTL for the metadata cached by this transport. Note that the value
	// configured here is an upper bound, the transport randomizes the TTLs to
	// avoid getting into states where multiple clients end up synchronized and
	// cause bursts of requests to the kafka broker.
	//
	// Default to 6s.
	MetadataTTL time.Duration

	// Unique identifier that the transport communicates to the brokers when it
	// sends requests.
	ClientID string

	// An optional configuration for TLS connections established by this
	// transport.
	//
	// If the Server
	TLS *tls.Config

	// SASL configures the Transfer to use SASL authentication.
	SASL sasl.Mechanism

	// An optional resolver used to translate broker host names into network
	// addresses.
	//
	// The resolver will be called for every request (not every connection),
	// making it possible to implement ACL policies by validating that the
	// program is allowed to connect to the kafka broker. This also means that
	// the resolver should probably provide a caching layer to avoid storming
	// the service discovery backend with requests.
	//
	// When set, the Dial function is not responsible for performing name
	// resolution, and is always called with a pre-resolved address.
	Resolver BrokerResolver

	// The background context used to control goroutines started internally by
	// the transport.
	//
	// If nil, context.Background() is used instead.
	Context context.Context

	mutex sync.RWMutex
	pools map[networkAddress]*connPool
}

// DefaultTransport is the default transport used by kafka clients in this
// package.
var DefaultTransport RoundTripper = &Transport{
	Dial: (&net.Dialer{
		Timeout:   3 * time.Second,
		DualStack: true,
	}).DialContext,
}

// CloseIdleConnections closes all idle connections immediately, and marks all
// connections that are in use to be closed when they become idle again.
func (t *Transport) CloseIdleConnections() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	for _, pool := range t.pools {
		pool.unref()
	}

	for k := range t.pools {
		delete(t.pools, k)
	}
}

// RoundTrip sends a request to a kafka cluster and returns the response, or an
// error if no responses were received.
//
// Message types are available in sub-packages of the protocol package. Each
// kafka API is implemented in a different sub-package. For example, the request
// and response types for the Fetch API are available in the protocol/fetch
// package.
//
// The type of the response message will match the type of the request. For
// exmple, if RoundTrip was called with a *fetch.Request as argument, the value
// returned will be of type *fetch.Response. It is safe for the program to do a
// type assertion after checking that no error was returned.
//
// This example illustrates the way this method is expected to be used:
//
//	r, err := transport.RoundTrip(ctx, addr, &fetch.Request{ ... })
//	if err != nil {
//		...
//	} else {
//		res := r.(*fetch.Response)
//		...
//	}
//
// The transport automatically selects the highest version of the API that is
// supported by both the kafka-go package and the kafka broker. The negotiation
// happens transparently once when connections are established.
//
// This API was introduced in version 0.4 as a way to leverage the lower-level
// features of the kafka protocol, but also provide a more efficient way of
// managing connections to kafka brokers.
func (t *Transport) RoundTrip(ctx context.Context, addr net.Addr, req Request) (Response, error) {
	p := t.grabPool(addr)
	defer p.unref()
	return p.roundTrip(ctx, req)
}

func (t *Transport) dial() func(context.Context, string, string) (net.Conn, error) {
	if t.Dial != nil {
		return t.Dial
	}
	return defaultDialer.DialContext
}

func (t *Transport) dialTimeout() time.Duration {
	if t.DialTimeout > 0 {
		return t.DialTimeout
	}
	return 5 * time.Second
}

func (t *Transport) idleTimeout() time.Duration {
	if t.IdleTimeout > 0 {
		return t.IdleTimeout
	}
	return 30 * time.Second
}

func (t *Transport) metadataTTL() time.Duration {
	if t.MetadataTTL > 0 {
		return t.MetadataTTL
	}
	return 6 * time.Second
}

func (t *Transport) grabPool(addr net.Addr) *connPool {
	k := networkAddress{
		network: addr.Network(),
		address: addr.String(),
	}

	t.mutex.RLock()
	p := t.pools[k]
	if p != nil {
		p.ref()
	}
	t.mutex.RUnlock()

	if p != nil {
		return p
	}

	t.mutex.Lock()
	defer t.mutex.Unlock()

	if p := t.pools[k]; p != nil {
		p.ref()
		return p
	}

	ctx, cancel := context.WithCancel(t.context())

	p = &connPool{
		refc: 2,

		dial:        t.dial(),
		dialTimeout: t.dialTimeout(),
		idleTimeout: t.idleTimeout(),
		metadataTTL: t.metadataTTL(),
		clientID:    t.ClientID,
		tls:         t.TLS,
		sasl:        t.SASL,
		resolver:    t.Resolver,

		ready:  make(event),
		wake:   make(chan event),
		conns:  make(map[int32]*connGroup),
		cancel: cancel,
	}

	p.ctrl = p.newConnGroup(addr)
	go p.discover(ctx, p.wake)

	if t.pools == nil {
		t.pools = make(map[networkAddress]*connPool)
	}
	t.pools[k] = p
	return p
}

func (t *Transport) context() context.Context {
	if t.Context != nil {
		return t.Context
	}
	return context.Background()
}

type event chan struct{}

func (e event) trigger() { close(e) }

type connPool struct {
	refc uintptr
	// Immutable fields of the connection pool. Connections access these field
	// on their parent pool in a ready-only fashion, so no synchronization is
	// required.
	dial        func(context.Context, string, string) (net.Conn, error)
	dialTimeout time.Duration
	idleTimeout time.Duration
	metadataTTL time.Duration
	clientID    string
	tls         *tls.Config
	sasl        sasl.Mechanism
	resolver    BrokerResolver
	// Signaling mechanisms to orchestrate communications between the pool and
	// the rest of the program.
	once   sync.Once  // ensure that `ready` is triggered only once
	ready  event      // triggered after the first metadata update
	wake   chan event // used to force metadata updates
	cancel context.CancelFunc
	// Mutable fields of the connection pool, access must be synchronized.
	mutex sync.RWMutex
	conns map[int32]*connGroup // data connections used for produce/fetch/etc...
	ctrl  *connGroup           // control connections used for metadata requests
	state atomic.Value         // cached cluster state
}

type connPoolState struct {
	metadata *meta.Response   // last metadata response seen by the pool
	err      error            // last error from metadata requests
	layout   protocol.Cluster // cluster layout built from metadata response
}

func (p *connPool) grabState() connPoolState {
	state, _ := p.state.Load().(connPoolState)
	return state
}

func (p *connPool) setState(state connPoolState) {
	p.state.Store(state)
}

func (p *connPool) ref() {
	atomic.AddUintptr(&p.refc, +1)
}

func (p *connPool) unref() {
	if atomic.AddUintptr(&p.refc, ^uintptr(0)) == 0 {
		p.mutex.Lock()
		defer p.mutex.Unlock()

		for _, conns := range p.conns {
			conns.closeIdleConns()
		}

		p.ctrl.closeIdleConns()
		p.cancel()
	}
}

func (p *connPool) roundTrip(ctx context.Context, req Request) (Response, error) {
	// This first select should never block after the first metadata response
	// that would mark the pool as `ready`.
	select {
	case <-p.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	state := p.grabState()
	var response promise

	switch m := req.(type) {
	case *meta.Request:
		// We serve metadata requests directly from the transport cache unless
		// we would like to auto create a topic that isn't in our cache.
		//
		// This reduces the number of round trips to kafka brokers while keeping
		// the logic simple when applying partitioning strategies.
		if state.err != nil {
			return nil, state.err
		}

		cachedMeta := filterMetadataResponse(m, state.metadata)
		// requestNeeded indicates if we need to send this metadata request to the server.
		// It's true when we want to auto-create topics and we don't have the topic in our
		// cache.
		var requestNeeded bool
		if m.AllowAutoTopicCreation {
			for _, topic := range cachedMeta.Topics {
				if topic.ErrorCode == int16(UnknownTopicOrPartition) {
					requestNeeded = true
					break
				}
			}
		}

		if !requestNeeded {
			return cachedMeta, nil
		}

	case protocol.Splitter:
		// Messages that implement the Splitter interface trigger the creation of
		// multiple requests that are all merged back into a single results by
		// a merger.
		messages, merger, err := m.Split(state.layout)
		if err != nil {
			return nil, err
		}
		promises := make([]promise, len(messages))
		for i, m := range messages {
			promises[i] = p.sendRequest(ctx, m, state)
		}
		response = join(promises, messages, merger)
	}

	if response == nil {
		response = p.sendRequest(ctx, req, state)
	}

	r, err := response.await(ctx)
	if err != nil {
		return r, err
	}

	switch resp := r.(type) {
	case *createtopics.Response:
		// Force an update of the metadata when adding topics,
		// otherwise the cached state would get out of sync.
		topicsToRefresh := make([]string, 0, len(resp.Topics))
		for _, topic := range resp.Topics {
			// fixes issue 672: don't refresh topics that failed to create, it causes the library to hang indefinitely
			if topic.ErrorCode != 0 {
				continue
			}

			topicsToRefresh = append(topicsToRefresh, topic.Name)
		}

		p.refreshMetadata(ctx, topicsToRefresh)
	case *meta.Response:
		m := req.(*meta.Request)
		// If we get here with allow auto topic creation then
		// we didn't have that topic in our cache so we should update
		// the cache.
		if m.AllowAutoTopicCreation {
			topicsToRefresh := make([]string, 0, len(resp.Topics))
			for _, topic := range resp.Topics {
				// fixes issue 806: don't refresh topics that failed to create,
				// it may means kafka doesn't enable auto topic creation.
				// This causes the library to hang indefinitely, same as createtopics process.
				if topic.ErrorCode != 0 {
					continue
				}

				topicsToRefresh = append(topicsToRefresh, topic.Name)
			}
			p.refreshMetadata(ctx, topicsToRefresh)
		}
	}

	return r, nil
}

// refreshMetadata forces an update of the cached cluster metadata, and waits
// for the given list of topics to appear. This waiting mechanism is necessary
// to account for the fact that topic creation is asynchronous in kafka, and
// causes subsequent requests to fail while the cluster state is propagated to
// all the brokers.
func (p *connPool) refreshMetadata(ctx context.Context, expectTopics []string) {
	minBackoff := 100 * time.Millisecond
	maxBackoff := 2 * time.Second
	cancel := ctx.Done()

	for ctx.Err() == nil {
		notify := make(event)
		select {
		case <-cancel:
			return
		case p.wake <- notify:
			select {
			case <-notify:
			case <-cancel:
				return
			}
		}

		state := p.grabState()
		found := 0

		for _, topic := range expectTopics {
			if _, ok := state.layout.Topics[topic]; ok {
				found++
			}
		}

		if found == len(expectTopics) {
			return
		}

		if delay := time.Duration(rand.Int63n(int64(minBackoff))); delay > 0 {
			timer := time.NewTimer(minBackoff)
			select {
			case <-cancel:
			case <-timer.C:
			}
			timer.Stop()

			if minBackoff *= 2; minBackoff > maxBackoff {
				minBackoff = maxBackoff
			}
		}
	}
}

func (p *connPool) setReady() {
	p.once.Do(p.ready.trigger)
}

// update is called periodically by the goroutine running the discover method
// to refresh the cluster layout information used by the transport to route
// requests to brokers.
func (p *connPool) update(ctx context.Context, metadata *meta.Response, err error) {
	var layout protocol.Cluster

	if metadata != nil {
		metadata.ThrottleTimeMs = 0

		// Normalize the lists so we can apply binary search on them.
		sortMetadataBrokers(metadata.Brokers)
		sortMetadataTopics(metadata.Topics)

		for i := range metadata.Topics {
			t := &metadata.Topics[i]
			sortMetadataPartitions(t.Partitions)
		}

		layout = makeLayout(metadata)
	}

	state := p.grabState()
	addBrokers := make(map[int32]struct{})
	delBrokers := make(map[int32]struct{})

	if err != nil {
		// Only update the error on the transport if the cluster layout was
		// unknown. This ensures that we prioritize a previously known state
		// of the cluster to reduce the impact of transient failures.
		if state.metadata != nil {
			return
		}
		state.err = err
	} else {
		for id, b2 := range layout.Brokers {
			if b1, ok := state.layout.Brokers[id]; !ok {
				addBrokers[id] = struct{}{}
			} else if b1 != b2 {
				addBrokers[id] = struct{}{}
				delBrokers[id] = struct{}{}
			}
		}

		for id := range state.layout.Brokers {
			if _, ok := layout.Brokers[id]; !ok {
				delBrokers[id] = struct{}{}
			}
		}

		state.metadata, state.layout = metadata, layout
		state.err = nil
	}

	defer p.setReady()
	defer p.setState(state)

	if len(addBrokers) != 0 || len(delBrokers) != 0 {
		// Only acquire the lock when there is a change of layout. This is an
		// infrequent event so we don't risk introducing regular contention on
		// the mutex if we were to lock it on every update.
		p.mutex.Lock()
		defer p.mutex.Unlock()

		if ctx.Err() != nil {
			return // the pool has been closed, no need to update
		}

		for id := range delBrokers {
			if broker := p.conns[id]; broker != nil {
				broker.closeIdleConns()
				delete(p.conns, id)
			}
		}

		for id := range addBrokers {
			broker := layout.Brokers[id]
			p.conns[id] = p.newBrokerConnGroup(Broker{
				Rack: broker.Rack,
				Host: broker.Host,
				Port: int(broker.Port),
				ID:   int(broker.ID),
			})
		}
	}
}

// discover is the entry point of an internal goroutine for the transport which
// periodically requests updates of the cluster metadata and refreshes the
// transport cached cluster layout.
func (p *connPool) discover(ctx context.Context, wake <-chan event) {
	prng := rand.New(rand.NewSource(time.Now().UnixNano()))
	metadataTTL := func() time.Duration {
		return time.Duration(prng.Int63n(int64(p.metadataTTL)))
	}

	timer := time.NewTimer(metadataTTL())
	defer timer.Stop()

	var notify event
	done := ctx.Done()

	for {
		c, err := p.grabClusterConn(ctx)
		if err != nil {
			p.update(ctx, nil, err)
		} else {
			res := make(async, 1)
			req := &meta.Request{}
			deadline, cancel := context.WithTimeout(ctx, p.metadataTTL)
			c.reqs <- connRequest{
				ctx: deadline,
				req: req,
				res: res,
			}
			r, err := res.await(deadline)
			cancel()
			if err != nil && errors.Is(err, ctx.Err()) {
				return
			}
			ret, _ := r.(*meta.Response)
			p.update(ctx, ret, err)
		}

		if notify != nil {
			notify.trigger()
			notify = nil
		}

		select {
		case <-timer.C:
			timer.Reset(metadataTTL())
		case <-done:
			return
		case notify = <-wake:
		}
	}
}

// grabBrokerConn returns a connection to a specific broker represented by the
// broker id passed as argument. If the broker id was not known, an error is
// returned.
func (p *connPool) grabBrokerConn(ctx context.Context, brokerID int32) (*conn, error) {
	p.mutex.RLock()
	g := p.conns[brokerID]
	p.mutex.RUnlock()
	if g == nil {
		return nil, BrokerNotAvailable
	}
	return g.grabConnOrConnect(ctx)
}

// grabClusterConn returns the connection to the kafka cluster that the pool is
// configured to connect to.
//
// The transport uses a shared `control` connection to the cluster for any
// requests that aren't supposed to be sent to specific brokers (e.g. Fetch or
// Produce requests). Requests intended to be routed to specific brokers are
// dispatched on a separate pool of connections that the transport maintains.
// This split help avoid head-of-line blocking situations where control requests
// like Metadata would be queued behind large responses from Fetch requests for
// example.
//
// In either cases, the requests are multiplexed so we can keep a minimal number
// of connections open (N+1, where N is the number of brokers in the cluster).
func (p *connPool) grabClusterConn(ctx context.Context) (*conn, error) {
	return p.ctrl.grabConnOrConnect(ctx)
}

func (p *connPool) sendRequest(ctx context.Context, req Request, state connPoolState) promise {
	brokerID := int32(-1)

	switch m := req.(type) {
	case protocol.BrokerMessage:
		// Some requests are supposed to be sent to specific brokers (e.g. the
		// partition leaders). They implement the BrokerMessage interface to
		// delegate the routing decision to each message type.
		broker, err := m.Broker(state.layout)
		if err != nil {
			return reject(err)
		}
		brokerID = broker.ID

	case protocol.GroupMessage:
		// Some requests are supposed to be sent to a group coordinator,
		// look up which broker is currently the coordinator for the group
		// so we can get a connection to that broker.
		//
		// TODO: should we cache the coordinator info?
		p := p.sendRequest(ctx, &findcoordinator.Request{Key: m.Group()}, state)
		r, err := p.await(ctx)
		if err != nil {
			return reject(err)
		}
		brokerID = r.(*findcoordinator.Response).NodeID
	case protocol.TransactionalMessage:
		p := p.sendRequest(ctx, &findcoordinator.Request{
			Key:     m.Transaction(),
			KeyType: int8(CoordinatorKeyTypeTransaction),
		}, state)
		r, err := p.await(ctx)
		if err != nil {
			return reject(err)
		}
		brokerID = r.(*findcoordinator.Response).NodeID
	}

	var c *conn
	var err error
	if brokerID >= 0 {
		c, err = p.grabBrokerConn(ctx, brokerID)
	} else {
		c, err = p.grabClusterConn(ctx)
	}
	if err != nil {
		return reject(err)
	}

	res := make(async, 1)

	c.reqs <- connRequest{
		ctx: ctx,
		req: req,
		res: res,
	}

	return res
}

func filterMetadataResponse(req *meta.Request, res *meta.Response) *meta.Response {
	ret := *res

	if req.TopicNames != nil {
		ret.Topics = make([]meta.ResponseTopic, len(req.TopicNames))

		for i, topicName := range req.TopicNames {
			j, ok := findMetadataTopic(res.Topics, topicName)
			if ok {
				ret.Topics[i] = res.Topics[j]
			} else {
				ret.Topics[i] = meta.ResponseTopic{
					ErrorCode: int16(UnknownTopicOrPartition),
					Name:      topicName,
				}
			}
		}
	}

	return &ret
}

func findMetadataTopic(topics []meta.ResponseTopic, topicName string) (int, bool) {
	i := sort.Search(len(topics), func(i int) bool {
		return topics[i].Name >= topicName
	})
	return i, i >= 0 && i < len(topics) && topics[i].Name == topicName
}

func sortMetadataBrokers(brokers []meta.ResponseBroker) {
	sort.Slice(brokers, func(i, j int) bool {
		return brokers[i].NodeID < brokers[j].NodeID
	})
}

func sortMetadataTopics(topics []meta.ResponseTopic) {
	sort.Slice(topics, func(i, j int) bool {
		return topics[i].Name < topics[j].Name
	})
}

func sortMetadataPartitions(partitions []meta.ResponsePartition) {
	sort.Slice(partitions, func(i, j int) bool {
		return partitions[i].PartitionIndex < partitions[j].PartitionIndex
	})
}

func makeLayout(metadataResponse *meta.Response) protocol.Cluster {
	layout := protocol.Cluster{
		Controller: metadataResponse.ControllerID,
		Brokers:    make(map[int32]protocol.Broker),
		Topics:     make(map[string]protocol.Topic),
	}

	for _, broker := range metadataResponse.Brokers {
		layout.Brokers[broker.NodeID] = protocol.Broker{
			Rack: broker.Rack,
			Host: broker.Host,
			Port: broker.Port,
			ID:   broker.NodeID,
		}
	}

	for _, topic := range metadataResponse.Topics {
		if topic.IsInternal {
			continue // TODO: do we need to expose those?
		}
		layout.Topics[topic.Name] = protocol.Topic{
			Name:       topic.Name,
			Error:      topic.ErrorCode,
			Partitions: makePartitions(topic.Partitions),
		}
	}

	return layout
}

func makePartitions(metadataPartitions []meta.ResponsePartition) map[int32]protocol.Partition {
	protocolPartitions := make(map[int32]protocol.Partition, len(metadataPartitions))
	numBrokerIDs := 0

	for _, p := range metadataPartitions {
		numBrokerIDs += len(p.ReplicaNodes) + len(p.IsrNodes) + len(p.OfflineReplicas)
	}

	// Reduce the memory footprint a bit by allocating a single buffer to write
	// all broker ids.
	brokerIDs := make([]int32, 0, numBrokerIDs)

	for _, p := range metadataPartitions {
		var rep, isr, off []int32
		brokerIDs, rep = appendBrokerIDs(brokerIDs, p.ReplicaNodes)
		brokerIDs, isr = appendBrokerIDs(brokerIDs, p.IsrNodes)
		brokerIDs, off = appendBrokerIDs(brokerIDs, p.OfflineReplicas)

		protocolPartitions[p.PartitionIndex] = protocol.Partition{
			ID:       p.PartitionIndex,
			Error:    p.ErrorCode,
			Leader:   p.LeaderID,
			Replicas: rep,
			ISR:      isr,
			Offline:  off,
		}
	}

	return protocolPartitions
}

func appendBrokerIDs(ids, brokers []int32) ([]int32, []int32) {
	i := len(ids)
	ids = append(ids, brokers...)
	return ids, ids[i:len(ids):len(ids)]
}

func (p *connPool) newConnGroup(a net.Addr) *connGroup {
	return &connGroup{
		addr: a,
		pool: p,
		broker: Broker{
			ID: -1,
		},
	}
}

func (p *connPool) newBrokerConnGroup(broker Broker) *connGroup {
	return &connGroup{
		addr: &networkAddress{
			network: "tcp",
			address: net.JoinHostPort(broker.Host, strconv.Itoa(broker.Port)),
		},
		pool:   p,
		broker: broker,
	}
}

type connRequest struct {
	ctx context.Context
	req Request
	res async
}

// The promise interface is used as a message passing abstraction to coordinate
// between goroutines that handle requests and responses.
type promise interface {
	// Waits until the promise is resolved, rejected, or the context canceled.
	await(context.Context) (Response, error)
}

// async is an implementation of the promise interface which supports resolving
// or rejecting the await call asynchronously.
type async chan interface{}

func (p async) await(ctx context.Context) (Response, error) {
	select {
	case x := <-p:
		switch v := x.(type) {
		case nil:
			return nil, nil // A nil response is ok (e.g. when RequiredAcks is None)
		case Response:
			return v, nil
		case error:
			return nil, v
		default:
			panic(fmt.Errorf("BUG: promise resolved with impossible value of type %T", v))
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p async) resolve(res Response) { p <- res }

func (p async) reject(err error) { p <- err }

// rejected is an implementation of the promise interface which is always
// returns an error. Values of this type are constructed using the reject
// function.
type rejected struct{ err error }

func reject(err error) promise { return &rejected{err: err} }

func (p *rejected) await(ctx context.Context) (Response, error) {
	return nil, p.err
}

// joined is an implementation of the promise interface which merges results
// from multiple promises into one await call using a merger.
type joined struct {
	promises []promise
	requests []Request
	merger   protocol.Merger
}

func join(promises []promise, requests []Request, merger protocol.Merger) promise {
	return &joined{
		promises: promises,
		requests: requests,
		merger:   merger,
	}
}

func (p *joined) await(ctx context.Context) (Response, error) {
	results := make([]interface{}, len(p.promises))

	for i, sub := range p.promises {
		m, err := sub.await(ctx)
		if err != nil {
			results[i] = err
		} else {
			results[i] = m
		}
	}

	return p.merger.Merge(p.requests, results)
}

// Default dialer used by the transport connections when no Dial function
// was configured by the program.
var defaultDialer = net.Dialer{
	Timeout:   3 * time.Second,
	DualStack: true,
}

// connGroup represents a logical connection group to a kafka broker. The
// actual network connections are lazily open before sending requests, and
// closed if they are unused for longer than the idle timeout.
type connGroup struct {
	addr   net.Addr
	broker Broker
	// Immutable state of the connection.
	pool *connPool
	// Shared state of the connection, this is synchronized on the mutex through
	// calls to the synchronized method. Both goroutines of the connection share
	// the state maintained in these fields.
	mutex     sync.Mutex
	closed    bool
	idleConns []*conn // stack of idle connections
}

func (g *connGroup) closeIdleConns() {
	g.mutex.Lock()
	conns := g.idleConns
	g.idleConns = nil
	g.closed = true
	g.mutex.Unlock()

	for _, c := range conns {
		c.close()
	}
}

func (g *connGroup) grabConnOrConnect(ctx context.Context) (*conn, error) {
	rslv := g.pool.resolver
	addr := g.addr
	var c *conn

	if rslv == nil {
		c = g.grabConn()
	} else {
		var err error
		broker := g.broker

		if broker.ID < 0 {
			host, port, err := splitHostPortNumber(addr.String())
			if err != nil {
				return nil, err
			}
			broker.Host = host
			broker.Port = port
		}

		ipAddrs, err := rslv.LookupBrokerIPAddr(ctx, broker)
		if err != nil {
			return nil, err
		}

		for _, ipAddr := range ipAddrs {
			network := addr.Network()
			address := net.JoinHostPort(ipAddr.String(), strconv.Itoa(broker.Port))

			if c = g.grabConnTo(network, address); c != nil {
				break
			}
		}
	}

	if c == nil {
		connChan := make(chan *conn)
		errChan := make(chan error)

		go func() {
			c, err := g.connect(ctx, addr)
			if err != nil {
				select {
				case errChan <- err:
				case <-ctx.Done():
				}
			} else {
				select {
				case connChan <- c:
				case <-ctx.Done():
					if !g.releaseConn(c) {
						c.close()
					}
				}
			}
		}()

		select {
		case c = <-connChan:
		case err := <-errChan:
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return c, nil
}

func (g *connGroup) grabConnTo(network, address string) *conn {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	for i := len(g.idleConns) - 1; i >= 0; i-- {
		c := g.idleConns[i]

		if c.network == network && c.address == address {
			copy(g.idleConns[i:], g.idleConns[i+1:])
			n := len(g.idleConns) - 1
			g.idleConns[n] = nil
			g.idleConns = g.idleConns[:n]

			if c.timer != nil {
				c.timer.Stop()
			}

			return c
		}
	}

	return nil
}

func (g *connGroup) grabConn() *conn {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if len(g.idleConns) == 0 {
		return nil
	}

	n := len(g.idleConns) - 1
	c := g.idleConns[n]
	g.idleConns[n] = nil
	g.idleConns = g.idleConns[:n]

	if c.timer != nil {
		c.timer.Stop()
	}

	return c
}

func (g *connGroup) removeConn(c *conn) bool {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if c.timer != nil {
		c.timer.Stop()
	}

	for i, x := range g.idleConns {
		if x == c {
			copy(g.idleConns[i:], g.idleConns[i+1:])
			n := len(g.idleConns) - 1
			g.idleConns[n] = nil
			g.idleConns = g.idleConns[:n]
			return true
		}
	}

	return false
}

func (g *connGroup) releaseConn(c *conn) bool {
	idleTimeout := g.pool.idleTimeout

	g.mutex.Lock()
	defer g.mutex.Unlock()

	if g.closed {
		return false
	}

	if c.timer != nil {
		c.timer.Reset(idleTimeout)
	} else {
		c.timer = time.AfterFunc(idleTimeout, func() {
			if g.removeConn(c) {
				c.close()
			}
		})
	}

	g.idleConns = append(g.idleConns, c)
	return true
}

func (g *connGroup) connect(ctx context.Context, addr net.Addr) (*conn, error) {
	deadline := time.Now().Add(g.pool.dialTimeout)

	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	network := strings.Split(addr.Network(), ",")
	address := strings.Split(addr.String(), ",")
	var netConn net.Conn
	var netAddr net.Addr
	var err error

	if len(address) > 1 {
		// Shuffle the list of addresses to randomize the order in which
		// connections are attempted. This prevents routing all connections
		// to the first broker (which will usually succeed).
		rand.Shuffle(len(address), func(i, j int) {
			network[i], network[j] = network[j], network[i]
			address[i], address[j] = address[j], address[i]
		})
	}

	for i := range address {
		netConn, err = g.pool.dial(ctx, network[i], address[i])
		if err == nil {
			netAddr = &networkAddress{
				network: network[i],
				address: address[i],
			}
			break
		}
	}

	if err != nil {
		return nil, err
	}

	defer func() {
		if netConn != nil {
			netConn.Close()
		}
	}()

	if tlsConfig := g.pool.tls; tlsConfig != nil {
		if tlsConfig.ServerName == "" {
			host, _ := splitHostPort(netAddr.String())
			tlsConfig = tlsConfig.Clone()
			tlsConfig.ServerName = host
		}
		netConn = tls.Client(netConn, tlsConfig)
	}

	pc := protocol.NewConn(netConn, g.pool.clientID)
	pc.SetDeadline(deadline)

	r, err := pc.RoundTrip(new(apiversions.Request))
	if err != nil {
		return nil, err
	}
	res := r.(*apiversions.Response)
	ver := make(map[protocol.ApiKey]int16, len(res.ApiKeys))

	if res.ErrorCode != 0 {
		return nil, fmt.Errorf("negotating API versions with kafka broker at %s: %w", g.addr, Error(res.ErrorCode))
	}

	for _, r := range res.ApiKeys {
		apiKey := protocol.ApiKey(r.ApiKey)
		ver[apiKey] = apiKey.SelectVersion(r.MinVersion, r.MaxVersion)
	}

	pc.SetVersions(ver)
	pc.SetDeadline(time.Time{})

	if g.pool.sasl != nil {
		host, port, err := splitHostPortNumber(netAddr.String())
		if err != nil {
			return nil, err
		}
		metadata := &sasl.Metadata{
			Host: host,
			Port: port,
		}
		if err := authenticateSASL(sasl.WithMetadata(ctx, metadata), pc, g.pool.sasl); err != nil {
			return nil, err
		}
	}

	reqs := make(chan connRequest)
	c := &conn{
		network: netAddr.Network(),
		address: netAddr.String(),
		reqs:    reqs,
		group:   g,
	}
	go c.run(pc, reqs)

	netConn = nil
	return c, nil
}

type conn struct {
	reqs    chan<- connRequest
	network string
	address string
	once    sync.Once
	group   *connGroup
	timer   *time.Timer
}

func (c *conn) close() {
	c.once.Do(func() { close(c.reqs) })
}

func (c *conn) run(pc *protocol.Conn, reqs <-chan connRequest) {
	defer pc.Close()

	for cr := range reqs {
		r, err := c.roundTrip(cr.ctx, pc, cr.req)
		if err != nil {
			cr.res.reject(err)
			if !errors.Is(err, protocol.ErrNoRecord) {
				break
			}
		} else {
			cr.res.resolve(r)
		}
		if !c.group.releaseConn(c) {
			break
		}
	}
}

func (c *conn) roundTrip(ctx context.Context, pc *protocol.Conn, req Request) (Response, error) {
	pprof.SetGoroutineLabels(ctx)
	defer pprof.SetGoroutineLabels(context.Background())

	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		pc.SetDeadline(deadline)
		defer pc.SetDeadline(time.Time{})
	}

	return pc.RoundTrip(req)
}

// authenticateSASL performs all of the required requests to authenticate this
// connection.  If any step fails, this function returns with an error.  A nil
// error indicates successful authentication.
func authenticateSASL(ctx context.Context, pc *protocol.Conn, mechanism sasl.Mechanism) error {
	if err := saslHandshakeRoundTrip(pc, mechanism.Name()); err != nil {
		return err
	}

	sess, state, err := mechanism.Start(ctx)
	if err != nil {
		return err
	}

	for completed := false; !completed; {
		challenge, err := saslAuthenticateRoundTrip(pc, state)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// the broker may communicate a failed exchange by closing the
				// connection (esp. in the case where we're passing opaque sasl
				// data over the wire since there's no protocol info).
				return SASLAuthenticationFailed
			}

			return err
		}

		completed, state, err = sess.Next(ctx, challenge)
		if err != nil {
			return err
		}
	}

	return nil
}

// saslHandshake sends the SASL handshake message.  This will determine whether
// the Mechanism is supported by the cluster.  If it's not, this function will
// error out with UnsupportedSASLMechanism.
//
// If the mechanism is unsupported, the handshake request will reply with the
// list of the cluster's configured mechanisms, which could potentially be used
// to facilitate negotiation.  At the moment, we are not negotiating the
// mechanism as we believe that brokers are usually known to the client, and
// therefore the client should already know which mechanisms are supported.
//
// See http://kafka.apache.org/protocol.html#The_Messages_SaslHandshake
func saslHandshakeRoundTrip(pc *protocol.Conn, mechanism string) error {
	msg, err := pc.RoundTrip(&saslhandshake.Request{
		Mechanism: mechanism,
	})
	if err != nil {
		return err
	}
	res := msg.(*saslhandshake.Response)
	if res.ErrorCode != 0 {
		err = Error(res.ErrorCode)
	}
	return err
}

// saslAuthenticate sends the SASL authenticate message.  This function must
// be immediately preceded by a successful saslHandshake.
//
// See http://kafka.apache.org/protocol.html#The_Messages_SaslAuthenticate
func saslAuthenticateRoundTrip(pc *protocol.Conn, data []byte) ([]byte, error) {
	msg, err := pc.RoundTrip(&saslauthenticate.Request{
		AuthBytes: data,
	})
	if err != nil {
		return nil, err
	}
	res := msg.(*saslauthenticate.Response)
	if res.ErrorCode != 0 {
		err = makeError(res.ErrorCode, res.ErrorMessage)
	}
	return res.AuthBytes, err
}

var _ RoundTripper = (*Transport)(nil)
