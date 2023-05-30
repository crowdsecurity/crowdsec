package kafka

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	metadataAPI "github.com/segmentio/kafka-go/protocol/metadata"
)

// The Writer type provides the implementation of a producer of kafka messages
// that automatically distributes messages across partitions of a single topic
// using a configurable balancing policy.
//
// Writes manage the dispatch of messages across partitions of the topic they
// are configured to write to using a Balancer, and aggregate batches to
// optimize the writes to kafka.
//
// Writers may be configured to be used synchronously or asynchronously. When
// use synchronously, calls to WriteMessages block until the messages have been
// written to kafka. In this mode, the program should inspect the error returned
// by the function and test if it an instance of kafka.WriteErrors in order to
// identify which messages have succeeded or failed, for example:
//
//	// Construct a synchronous writer (the default mode).
//	w := &kafka.Writer{
//		Addr:         Addr: kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
//		Topic:        "topic-A",
//		RequiredAcks: kafka.RequireAll,
//	}
//
//	...
//
//  // Passing a context can prevent the operation from blocking indefinitely.
//	switch err := w.WriteMessages(ctx, msgs...).(type) {
//	case nil:
//	case kafka.WriteErrors:
//		for i := range msgs {
//			if err[i] != nil {
//				// handle the error writing msgs[i]
//				...
//			}
//		}
//	default:
//		// handle other errors
//		...
//	}
//
// In asynchronous mode, the program may configure a completion handler on the
// writer to receive notifications of messages being written to kafka:
//
//	w := &kafka.Writer{
//		Addr:         Addr: kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
//		Topic:        "topic-A",
//		RequiredAcks: kafka.RequireAll,
//		Async:        true, // make the writer asynchronous
//		Completion: func(messages []kafka.Message, err error) {
//			...
//		},
//	}
//
//	...
//
//	// Because the writer is asynchronous, there is no need for the context to
//	// be cancelled, the call will never block.
//	if err := w.WriteMessages(context.Background(), msgs...); err != nil {
//		// Only validation errors would be reported in this case.
//		...
//	}
//
// Methods of Writer are safe to use concurrently from multiple goroutines,
// however the writer configuration should not be modified after first use.
type Writer struct {
	// Address of the kafka cluster that this writer is configured to send
	// messages to.
	//
	// This field is required, attempting to write messages to a writer with a
	// nil address will error.
	Addr net.Addr

	// Topic is the name of the topic that the writer will produce messages to.
	//
	// Setting this field or not is a mutually exclusive option. If you set Topic
	// here, you must not set Topic for any produced Message. Otherwise, if you	do
	// not set Topic, every Message must have Topic specified.
	Topic string

	// The balancer used to distribute messages across partitions.
	//
	// The default is to use a round-robin distribution.
	Balancer Balancer

	// Limit on how many attempts will be made to deliver a message.
	//
	// The default is to try at most 10 times.
	MaxAttempts int

	// Limit on how many messages will be buffered before being sent to a
	// partition.
	//
	// The default is to use a target batch size of 100 messages.
	BatchSize int

	// Limit the maximum size of a request in bytes before being sent to
	// a partition.
	//
	// The default is to use a kafka default value of 1048576.
	BatchBytes int64

	// Time limit on how often incomplete message batches will be flushed to
	// kafka.
	//
	// The default is to flush at least every second.
	BatchTimeout time.Duration

	// Timeout for read operations performed by the Writer.
	//
	// Defaults to 10 seconds.
	ReadTimeout time.Duration

	// Timeout for write operation performed by the Writer.
	//
	// Defaults to 10 seconds.
	WriteTimeout time.Duration

	// Number of acknowledges from partition replicas required before receiving
	// a response to a produce request, the following values are supported:
	//
	//  RequireNone (0)  fire-and-forget, do not wait for acknowledgements from the
	//  RequireOne  (1)  wait for the leader to acknowledge the writes
	//  RequireAll  (-1) wait for the full ISR to acknowledge the writes
	//
	// Defaults to RequireNone.
	RequiredAcks RequiredAcks

	// Setting this flag to true causes the WriteMessages method to never block.
	// It also means that errors are ignored since the caller will not receive
	// the returned value. Use this only if you don't care about guarantees of
	// whether the messages were written to kafka.
	//
	// Defaults to false.
	Async bool

	// An optional function called when the writer succeeds or fails the
	// delivery of messages to a kafka partition. When writing the messages
	// fails, the `err` parameter will be non-nil.
	//
	// The messages that the Completion function is called with have their
	// topic, partition, offset, and time set based on the Produce responses
	// received from kafka. All messages passed to a call to the function have
	// been written to the same partition. The keys and values of messages are
	// referencing the original byte slices carried by messages in the calls to
	// WriteMessages.
	//
	// The function is called from goroutines started by the writer. Calls to
	// Close will block on the Completion function calls. When the Writer is
	// not writing asynchronously, the WriteMessages call will also block on
	// Completion function, which is a useful guarantee if the byte slices
	// for the message keys and values are intended to be reused after the
	// WriteMessages call returned.
	//
	// If a completion function panics, the program terminates because the
	// panic is not recovered by the writer and bubbles up to the top of the
	// goroutine's call stack.
	Completion func(messages []Message, err error)

	// Compression set the compression codec to be used to compress messages.
	Compression Compression

	// If not nil, specifies a logger used to report internal changes within the
	// writer.
	Logger Logger

	// ErrorLogger is the logger used to report errors. If nil, the writer falls
	// back to using Logger instead.
	ErrorLogger Logger

	// A transport used to send messages to kafka clusters.
	//
	// If nil, DefaultTransport is used.
	Transport RoundTripper

	// AllowAutoTopicCreation notifies writer to create topic if missing.
	AllowAutoTopicCreation bool

	// Manages the current set of partition-topic writers.
	group   sync.WaitGroup
	mutex   sync.Mutex
	closed  bool
	writers map[topicPartition]*partitionWriter

	// writer stats are all made of atomic values, no need for synchronization.
	// Use a pointer to ensure 64-bit alignment of the values. The once value is
	// used to lazily create the value when first used, allowing programs to use
	// the zero-value value of Writer.
	once sync.Once
	*writerStats

	// If no balancer is configured, the writer uses this one. RoundRobin values
	// are safe to use concurrently from multiple goroutines, there is no need
	// for extra synchronization to access this field.
	roundRobin RoundRobin

	// non-nil when a transport was created by NewWriter, remove in 1.0.
	transport *Transport
}

// WriterConfig is a configuration type used to create new instances of Writer.
//
// DEPRECATED: writer values should be configured directly by assigning their
// exported fields. This type is kept for backward compatibility, and will be
// removed in version 1.0.
type WriterConfig struct {
	// The list of brokers used to discover the partitions available on the
	// kafka cluster.
	//
	// This field is required, attempting to create a writer with an empty list
	// of brokers will panic.
	Brokers []string

	// The topic that the writer will produce messages to.
	//
	// If provided, this will be used to set the topic for all produced messages.
	// If not provided, each Message must specify a topic for itself. This must be
	// mutually exclusive, otherwise the Writer will return an error.
	Topic string

	// The dialer used by the writer to establish connections to the kafka
	// cluster.
	//
	// If nil, the default dialer is used instead.
	Dialer *Dialer

	// The balancer used to distribute messages across partitions.
	//
	// The default is to use a round-robin distribution.
	Balancer Balancer

	// Limit on how many attempts will be made to deliver a message.
	//
	// The default is to try at most 10 times.
	MaxAttempts int

	// DEPRECATED: in versions prior to 0.4, the writer used channels internally
	// to dispatch messages to partitions. This has been replaced by an in-memory
	// aggregation of batches which uses shared state instead of message passing,
	// making this option unnecessary.
	QueueCapacity int

	// Limit on how many messages will be buffered before being sent to a
	// partition.
	//
	// The default is to use a target batch size of 100 messages.
	BatchSize int

	// Limit the maximum size of a request in bytes before being sent to
	// a partition.
	//
	// The default is to use a kafka default value of 1048576.
	BatchBytes int

	// Time limit on how often incomplete message batches will be flushed to
	// kafka.
	//
	// The default is to flush at least every second.
	BatchTimeout time.Duration

	// Timeout for read operations performed by the Writer.
	//
	// Defaults to 10 seconds.
	ReadTimeout time.Duration

	// Timeout for write operation performed by the Writer.
	//
	// Defaults to 10 seconds.
	WriteTimeout time.Duration

	// DEPRECATED: in versions prior to 0.4, the writer used to maintain a cache
	// the topic layout. With the change to use a transport to manage connections,
	// the responsibility of syncing the cluster layout has been delegated to the
	// transport.
	RebalanceInterval time.Duration

	// DEPRECATED: in versions prior to 0.4, the writer used to manage connections
	// to the kafka cluster directly. With the change to use a transport to manage
	// connections, the writer has no connections to manage directly anymore.
	IdleConnTimeout time.Duration

	// Number of acknowledges from partition replicas required before receiving
	// a response to a produce request. The default is -1, which means to wait for
	// all replicas, and a value above 0 is required to indicate how many replicas
	// should acknowledge a message to be considered successful.
	//
	// This version of kafka-go (v0.3) does not support 0 required acks, due to
	// some internal complexity implementing this with the Kafka protocol. If you
	// need that functionality specifically, you'll need to upgrade to v0.4.
	RequiredAcks int

	// Setting this flag to true causes the WriteMessages method to never block.
	// It also means that errors are ignored since the caller will not receive
	// the returned value. Use this only if you don't care about guarantees of
	// whether the messages were written to kafka.
	Async bool

	// CompressionCodec set the codec to be used to compress Kafka messages.
	CompressionCodec

	// If not nil, specifies a logger used to report internal changes within the
	// writer.
	Logger Logger

	// ErrorLogger is the logger used to report errors. If nil, the writer falls
	// back to using Logger instead.
	ErrorLogger Logger
}

type topicPartition struct {
	topic     string
	partition int32
}

// Validate method validates WriterConfig properties.
func (config *WriterConfig) Validate() error {
	if len(config.Brokers) == 0 {
		return errors.New("cannot create a kafka writer with an empty list of brokers")
	}
	return nil
}

// WriterStats is a data structure returned by a call to Writer.Stats that
// exposes details about the behavior of the writer.
type WriterStats struct {
	Writes   int64 `metric:"kafka.writer.write.count"     type:"counter"`
	Messages int64 `metric:"kafka.writer.message.count"   type:"counter"`
	Bytes    int64 `metric:"kafka.writer.message.bytes"   type:"counter"`
	Errors   int64 `metric:"kafka.writer.error.count"     type:"counter"`

	BatchTime  DurationStats `metric:"kafka.writer.batch.seconds"`
	WriteTime  DurationStats `metric:"kafka.writer.write.seconds"`
	WaitTime   DurationStats `metric:"kafka.writer.wait.seconds"`
	Retries    SummaryStats  `metric:"kafka.writer.retries.count"`
	BatchSize  SummaryStats  `metric:"kafka.writer.batch.size"`
	BatchBytes SummaryStats  `metric:"kafka.writer.batch.bytes"`

	MaxAttempts  int64         `metric:"kafka.writer.attempts.max"  type:"gauge"`
	MaxBatchSize int64         `metric:"kafka.writer.batch.max"     type:"gauge"`
	BatchTimeout time.Duration `metric:"kafka.writer.batch.timeout" type:"gauge"`
	ReadTimeout  time.Duration `metric:"kafka.writer.read.timeout"  type:"gauge"`
	WriteTimeout time.Duration `metric:"kafka.writer.write.timeout" type:"gauge"`
	RequiredAcks int64         `metric:"kafka.writer.acks.required" type:"gauge"`
	Async        bool          `metric:"kafka.writer.async"         type:"gauge"`

	Topic string `tag:"topic"`

	// DEPRECATED: these fields will only be reported for backward compatibility
	// if the Writer was constructed with NewWriter.
	Dials    int64         `metric:"kafka.writer.dial.count" type:"counter"`
	DialTime DurationStats `metric:"kafka.writer.dial.seconds"`

	// DEPRECATED: these fields were meaningful prior to kafka-go 0.4, changes
	// to the internal implementation and the introduction of the transport type
	// made them unnecessary.
	//
	// The values will be zero but are left for backward compatibility to avoid
	// breaking programs that used these fields.
	Rebalances        int64
	RebalanceInterval time.Duration
	QueueLength       int64
	QueueCapacity     int64
	ClientID          string
}

// writerStats is a struct that contains statistics on a writer.
//
// Since atomic is used to mutate the statistics the values must be 64-bit aligned.
// This is easily accomplished by always allocating this struct directly, (i.e. using a pointer to the struct).
// See https://golang.org/pkg/sync/atomic/#pkg-note-BUG
type writerStats struct {
	dials          counter
	writes         counter
	messages       counter
	bytes          counter
	errors         counter
	dialTime       summary
	batchTime      summary
	writeTime      summary
	waitTime       summary
	retries        summary
	batchSize      summary
	batchSizeBytes summary
}

// NewWriter creates and returns a new Writer configured with config.
//
// DEPRECATED: Writer value can be instantiated and configured directly,
// this function is retained for backward compatibility and will be removed
// in version 1.0.
func NewWriter(config WriterConfig) *Writer {
	if err := config.Validate(); err != nil {
		panic(err)
	}

	if config.Dialer == nil {
		config.Dialer = DefaultDialer
	}

	if config.Balancer == nil {
		config.Balancer = &RoundRobin{}
	}

	// Converts the pre-0.4 Dialer API into a Transport.
	kafkaDialer := DefaultDialer
	if config.Dialer != nil {
		kafkaDialer = config.Dialer
	}

	dialer := (&net.Dialer{
		Timeout:       kafkaDialer.Timeout,
		Deadline:      kafkaDialer.Deadline,
		LocalAddr:     kafkaDialer.LocalAddr,
		DualStack:     kafkaDialer.DualStack,
		FallbackDelay: kafkaDialer.FallbackDelay,
		KeepAlive:     kafkaDialer.KeepAlive,
	})

	var resolver Resolver
	if r, ok := kafkaDialer.Resolver.(*net.Resolver); ok {
		dialer.Resolver = r
	} else {
		resolver = kafkaDialer.Resolver
	}

	stats := new(writerStats)
	// For backward compatibility with the pre-0.4 APIs, support custom
	// resolvers by wrapping the dial function.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		start := time.Now()
		defer func() {
			stats.dials.observe(1)
			stats.dialTime.observe(int64(time.Since(start)))
		}()
		address, err := lookupHost(ctx, addr, resolver)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, address)
	}

	idleTimeout := config.IdleConnTimeout
	if idleTimeout == 0 {
		// Historical default value of WriterConfig.IdleTimeout, 9 minutes seems
		// like it is way too long when there is no ping mechanism in the kafka
		// protocol.
		idleTimeout = 9 * time.Minute
	}

	metadataTTL := config.RebalanceInterval
	if metadataTTL == 0 {
		// Historical default value of WriterConfig.RebalanceInterval.
		metadataTTL = 15 * time.Second
	}

	transport := &Transport{
		Dial:        dial,
		SASL:        kafkaDialer.SASLMechanism,
		TLS:         kafkaDialer.TLS,
		ClientID:    kafkaDialer.ClientID,
		IdleTimeout: idleTimeout,
		MetadataTTL: metadataTTL,
	}

	w := &Writer{
		Addr:         TCP(config.Brokers...),
		Topic:        config.Topic,
		MaxAttempts:  config.MaxAttempts,
		BatchSize:    config.BatchSize,
		Balancer:     config.Balancer,
		BatchBytes:   int64(config.BatchBytes),
		BatchTimeout: config.BatchTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
		RequiredAcks: RequiredAcks(config.RequiredAcks),
		Async:        config.Async,
		Logger:       config.Logger,
		ErrorLogger:  config.ErrorLogger,
		Transport:    transport,
		transport:    transport,
		writerStats:  stats,
	}

	if config.RequiredAcks == 0 {
		// Historically the writers created by NewWriter have used "all" as the
		// default value when 0 was specified.
		w.RequiredAcks = RequireAll
	}

	if config.CompressionCodec != nil {
		w.Compression = Compression(config.CompressionCodec.Code())
	}

	return w
}

// enter is called by WriteMessages to indicate that a new inflight operation
// has started, which helps synchronize with Close and ensure that the method
// does not return until all inflight operations were completed.
func (w *Writer) enter() bool {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.closed {
		return false
	}
	w.group.Add(1)
	return true
}

// leave is called by WriteMessages to indicate that the inflight operation has
// completed.
func (w *Writer) leave() { w.group.Done() }

// spawn starts an new asynchronous operation on the writer. This method is used
// instead of starting goroutines inline to help manage the state of the
// writer's wait group. The wait group is used to block Close calls until all
// inflight operations have completed, therefore automatically including those
// started with calls to spawn.
func (w *Writer) spawn(f func()) {
	w.group.Add(1)
	go func() {
		defer w.group.Done()
		f()
	}()
}

// Close flushes pending writes, and waits for all writes to complete before
// returning. Calling Close also prevents new writes from being submitted to
// the writer, further calls to WriteMessages and the like will fail with
// io.ErrClosedPipe.
func (w *Writer) Close() error {
	w.mutex.Lock()
	// Marking the writer as closed here causes future calls to WriteMessages to
	// fail with io.ErrClosedPipe. Mutation of this field is synchronized on the
	// writer's mutex to ensure that no more increments of the wait group are
	// performed afterwards (which could otherwise race with the Wait below).
	w.closed = true

	// close all writers to trigger any pending batches
	for _, writer := range w.writers {
		writer.close()
	}

	for partition := range w.writers {
		delete(w.writers, partition)
	}

	w.mutex.Unlock()
	w.group.Wait()

	if w.transport != nil {
		w.transport.CloseIdleConnections()
	}

	return nil
}

// WriteMessages writes a batch of messages to the kafka topic configured on this
// writer.
//
// Unless the writer was configured to write messages asynchronously, the method
// blocks until all messages have been written, or until the maximum number of
// attempts was reached.
//
// When sending synchronously and the writer's batch size is configured to be
// greater than 1, this method blocks until either a full batch can be assembled
// or the batch timeout is reached.  The batch size and timeouts are evaluated
// per partition, so the choice of Balancer can also influence the flushing
// behavior.  For example, the Hash balancer will require on average N * batch
// size messages to trigger a flush where N is the number of partitions.  The
// best way to achieve good batching behavior is to share one Writer amongst
// multiple go routines.
//
// When the method returns an error, it may be of type kafka.WriteError to allow
// the caller to determine the status of each message.
//
// The context passed as first argument may also be used to asynchronously
// cancel the operation. Note that in this case there are no guarantees made on
// whether messages were written to kafka. The program should assume that the
// whole batch failed and re-write the messages later (which could then cause
// duplicates).
func (w *Writer) WriteMessages(ctx context.Context, msgs ...Message) error {
	if w.Addr == nil {
		return errors.New("kafka.(*Writer).WriteMessages: cannot create a kafka writer with a nil address")
	}

	if !w.enter() {
		return io.ErrClosedPipe
	}
	defer w.leave()

	if len(msgs) == 0 {
		return nil
	}

	balancer := w.balancer()
	batchBytes := w.batchBytes()

	for i := range msgs {
		n := int64(msgs[i].size())
		if n > batchBytes {
			// This error is left for backward compatibility with historical
			// behavior, but it can yield O(N^2) behaviors. The expectations
			// are that the program will check if WriteMessages returned a
			// MessageTooLargeError, discard the message that was exceeding
			// the maximum size, and try again.
			return messageTooLarge(msgs, i)
		}
	}

	// We use int32 here to half the memory footprint (compared to using int
	// on 64 bits architectures). We map lists of the message indexes instead
	// of the message values for the same reason, int32 is 4 bytes, vs a full
	// Message value which is 100+ bytes and contains pointers and contributes
	// to increasing GC work.
	assignments := make(map[topicPartition][]int32)

	for i, msg := range msgs {
		topic, err := w.chooseTopic(msg)
		if err != nil {
			return err
		}

		numPartitions, err := w.partitions(ctx, topic)
		if err != nil {
			return err
		}

		partition := balancer.Balance(msg, loadCachedPartitions(numPartitions)...)

		key := topicPartition{
			topic:     topic,
			partition: int32(partition),
		}

		assignments[key] = append(assignments[key], int32(i))
	}

	batches := w.batchMessages(msgs, assignments)
	if w.Async {
		return nil
	}

	done := ctx.Done()
	hasErrors := false
	for batch := range batches {
		select {
		case <-done:
			return ctx.Err()
		case <-batch.done:
			if batch.err != nil {
				hasErrors = true
			}
		}
	}

	if !hasErrors {
		return nil
	}

	werr := make(WriteErrors, len(msgs))

	for batch, indexes := range batches {
		for _, i := range indexes {
			werr[i] = batch.err
		}
	}
	return werr
}

func (w *Writer) batchMessages(messages []Message, assignments map[topicPartition][]int32) map[*writeBatch][]int32 {
	var batches map[*writeBatch][]int32
	if !w.Async {
		batches = make(map[*writeBatch][]int32, len(assignments))
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.writers == nil {
		w.writers = map[topicPartition]*partitionWriter{}
	}

	for key, indexes := range assignments {
		writer := w.writers[key]
		if writer == nil {
			writer = newPartitionWriter(w, key)
			w.writers[key] = writer
		}
		wbatches := writer.writeMessages(messages, indexes)

		for batch, idxs := range wbatches {
			batches[batch] = idxs
		}
	}

	return batches
}

func (w *Writer) produce(key topicPartition, batch *writeBatch) (*ProduceResponse, error) {
	timeout := w.writeTimeout()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return w.client(timeout).Produce(ctx, &ProduceRequest{
		Partition:    int(key.partition),
		Topic:        key.topic,
		RequiredAcks: w.RequiredAcks,
		Compression:  w.Compression,
		Records: &writerRecords{
			msgs: batch.msgs,
		},
	})
}

func (w *Writer) partitions(ctx context.Context, topic string) (int, error) {
	client := w.client(w.readTimeout())
	// Here we use the transport directly as an optimization to avoid the
	// construction of temporary request and response objects made by the
	// (*Client).Metadata API.
	//
	// It is expected that the transport will optimize this request by
	// caching recent results (the kafka.Transport types does).
	r, err := client.transport().RoundTrip(ctx, client.Addr, &metadataAPI.Request{
		TopicNames:             []string{topic},
		AllowAutoTopicCreation: w.AllowAutoTopicCreation,
	})
	if err != nil {
		return 0, err
	}
	for _, t := range r.(*metadataAPI.Response).Topics {
		if t.Name == topic {
			// This should always hit, unless kafka has a bug.
			if t.ErrorCode != 0 {
				return 0, Error(t.ErrorCode)
			}
			return len(t.Partitions), nil
		}
	}
	return 0, UnknownTopicOrPartition
}

func (w *Writer) client(timeout time.Duration) *Client {
	return &Client{
		Addr:      w.Addr,
		Transport: w.Transport,
		Timeout:   timeout,
	}
}

func (w *Writer) balancer() Balancer {
	if w.Balancer != nil {
		return w.Balancer
	}
	return &w.roundRobin
}

func (w *Writer) maxAttempts() int {
	if w.MaxAttempts > 0 {
		return w.MaxAttempts
	}
	// TODO: this is a very high default, if something has failed 9 times it
	// seems unlikely it will succeed on the 10th attempt. However, it does
	// carry the risk to greatly increase the volume of requests sent to the
	// kafka cluster. We should consider reducing this default (3?).
	return 10
}

func (w *Writer) batchSize() int {
	if w.BatchSize > 0 {
		return w.BatchSize
	}
	return 100
}

func (w *Writer) batchBytes() int64 {
	if w.BatchBytes > 0 {
		return w.BatchBytes
	}
	return 1048576
}

func (w *Writer) batchTimeout() time.Duration {
	if w.BatchTimeout > 0 {
		return w.BatchTimeout
	}
	return 1 * time.Second
}

func (w *Writer) readTimeout() time.Duration {
	if w.ReadTimeout > 0 {
		return w.ReadTimeout
	}
	return 10 * time.Second
}

func (w *Writer) writeTimeout() time.Duration {
	if w.WriteTimeout > 0 {
		return w.WriteTimeout
	}
	return 10 * time.Second
}

func (w *Writer) withLogger(do func(Logger)) {
	if w.Logger != nil {
		do(w.Logger)
	}
}

func (w *Writer) withErrorLogger(do func(Logger)) {
	if w.ErrorLogger != nil {
		do(w.ErrorLogger)
	} else {
		w.withLogger(do)
	}
}

func (w *Writer) stats() *writerStats {
	w.once.Do(func() {
		// This field is not nil when the writer was constructed with NewWriter
		// to share the value with the dial function and count dials.
		if w.writerStats == nil {
			w.writerStats = new(writerStats)
		}
	})
	return w.writerStats
}

// Stats returns a snapshot of the writer stats since the last time the method
// was called, or since the writer was created if it is called for the first
// time.
//
// A typical use of this method is to spawn a goroutine that will periodically
// call Stats on a kafka writer and report the metrics to a stats collection
// system.
func (w *Writer) Stats() WriterStats {
	stats := w.stats()
	return WriterStats{
		Dials:        stats.dials.snapshot(),
		Writes:       stats.writes.snapshot(),
		Messages:     stats.messages.snapshot(),
		Bytes:        stats.bytes.snapshot(),
		Errors:       stats.errors.snapshot(),
		DialTime:     stats.dialTime.snapshotDuration(),
		BatchTime:    stats.batchTime.snapshotDuration(),
		WriteTime:    stats.writeTime.snapshotDuration(),
		WaitTime:     stats.waitTime.snapshotDuration(),
		Retries:      stats.retries.snapshot(),
		BatchSize:    stats.batchSize.snapshot(),
		BatchBytes:   stats.batchSizeBytes.snapshot(),
		MaxAttempts:  int64(w.MaxAttempts),
		MaxBatchSize: int64(w.BatchSize),
		BatchTimeout: w.BatchTimeout,
		ReadTimeout:  w.ReadTimeout,
		WriteTimeout: w.WriteTimeout,
		RequiredAcks: int64(w.RequiredAcks),
		Async:        w.Async,
		Topic:        w.Topic,
	}
}

func (w *Writer) chooseTopic(msg Message) (string, error) {
	// w.Topic and msg.Topic are mutually exclusive, meaning only 1 must be set
	// otherwise we will return an error.
	if w.Topic != "" && msg.Topic != "" {
		return "", errors.New("kafka.(*Writer): Topic must not be specified for both Writer and Message")
	} else if w.Topic == "" && msg.Topic == "" {
		return "", errors.New("kafka.(*Writer): Topic must be specified for Writer or Message")
	}

	// now we choose the topic, depending on which one is not empty
	if msg.Topic != "" {
		return msg.Topic, nil
	}

	return w.Topic, nil
}

type batchQueue struct {
	queue []*writeBatch

	// Pointers are used here to make `go vet` happy, and avoid copying mutexes.
	// It may be better to revert these to non-pointers and avoid the copies in
	// a different way.
	mutex *sync.Mutex
	cond  *sync.Cond

	closed bool
}

func (b *batchQueue) Put(batch *writeBatch) bool {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	defer b.cond.Broadcast()

	if b.closed {
		return false
	}
	b.queue = append(b.queue, batch)
	return true
}

func (b *batchQueue) Get() *writeBatch {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	for len(b.queue) == 0 && !b.closed {
		b.cond.Wait()
	}

	if len(b.queue) == 0 {
		return nil
	}

	batch := b.queue[0]
	b.queue[0] = nil
	b.queue = b.queue[1:]

	return batch
}

func (b *batchQueue) Close() {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	defer b.cond.Broadcast()

	b.closed = true
}

func newBatchQueue(initialSize int) batchQueue {
	bq := batchQueue{
		queue: make([]*writeBatch, 0, initialSize),
		mutex: &sync.Mutex{},
		cond:  &sync.Cond{},
	}

	bq.cond.L = bq.mutex

	return bq
}

// partitionWriter is a writer for a topic-partion pair. It maintains messaging order
// across batches of messages.
type partitionWriter struct {
	meta  topicPartition
	queue batchQueue

	mutex     sync.Mutex
	currBatch *writeBatch

	// reference to the writer that owns this batch. Used for the produce logic
	// as well as stat tracking
	w *Writer
}

func newPartitionWriter(w *Writer, key topicPartition) *partitionWriter {
	writer := &partitionWriter{
		meta:  key,
		queue: newBatchQueue(10),
		w:     w,
	}
	w.spawn(writer.writeBatches)
	return writer
}

func (ptw *partitionWriter) writeBatches() {
	for {
		batch := ptw.queue.Get()

		// The only time we can return nil is when the queue is closed
		// and empty. If the queue is closed that means
		// the Writer is closed so once we're here it's time to exit.
		if batch == nil {
			return
		}

		ptw.writeBatch(batch)
	}
}

func (ptw *partitionWriter) writeMessages(msgs []Message, indexes []int32) map[*writeBatch][]int32 {
	ptw.mutex.Lock()
	defer ptw.mutex.Unlock()

	batchSize := ptw.w.batchSize()
	batchBytes := ptw.w.batchBytes()

	var batches map[*writeBatch][]int32
	if !ptw.w.Async {
		batches = make(map[*writeBatch][]int32, 1)
	}

	for _, i := range indexes {
	assignMessage:
		batch := ptw.currBatch
		if batch == nil {
			batch = ptw.newWriteBatch()
			ptw.currBatch = batch
		}
		if !batch.add(msgs[i], batchSize, batchBytes) {
			batch.trigger()
			ptw.queue.Put(batch)
			ptw.currBatch = nil
			goto assignMessage
		}

		if batch.full(batchSize, batchBytes) {
			batch.trigger()
			ptw.queue.Put(batch)
			ptw.currBatch = nil
		}

		if !ptw.w.Async {
			batches[batch] = append(batches[batch], i)
		}
	}
	return batches
}

// ptw.w can be accessed here because this is called with the lock ptw.mutex already held.
func (ptw *partitionWriter) newWriteBatch() *writeBatch {
	batch := newWriteBatch(time.Now(), ptw.w.batchTimeout())
	ptw.w.spawn(func() { ptw.awaitBatch(batch) })
	return batch
}

// awaitBatch waits for a batch to either fill up or time out.
// If the batch is full it only stops the timer, if the timer
// expires it will queue the batch for writing if needed.
func (ptw *partitionWriter) awaitBatch(batch *writeBatch) {
	select {
	case <-batch.timer.C:
		ptw.mutex.Lock()
		// detach the batch from the writer if we're still attached
		// and queue for writing.
		// Only the current batch can expire, all previous batches were already written to the queue.
		// If writeMesseages locks pw.mutex after the timer fires but before this goroutine
		// can lock pw.mutex it will either have filled the batch and enqueued it which will mean
		// pw.currBatch != batch so we just move on.
		// Otherwise, we detach the batch from the ptWriter and enqueue it for writing.
		if ptw.currBatch == batch {
			ptw.queue.Put(batch)
			ptw.currBatch = nil
		}
		ptw.mutex.Unlock()
	case <-batch.ready:
		// The batch became full, it was removed from the ptwriter and its
		// ready channel was closed. We need to close the timer to avoid
		// having it leak until it expires.
		batch.timer.Stop()
	}
}

func (ptw *partitionWriter) writeBatch(batch *writeBatch) {
	stats := ptw.w.stats()
	stats.batchTime.observe(int64(time.Since(batch.time)))
	stats.batchSize.observe(int64(len(batch.msgs)))
	stats.batchSizeBytes.observe(batch.bytes)

	var res *ProduceResponse
	var err error
	key := ptw.meta
	for attempt, maxAttempts := 0, ptw.w.maxAttempts(); attempt < maxAttempts; attempt++ {
		if attempt != 0 {
			stats.retries.observe(1)
			// TODO: should there be a way to asynchronously cancel this
			// operation?
			//
			// * If all goroutines that added message to this batch have stopped
			//   waiting for it, should we abort?
			//
			// * If the writer has been closed? It reduces the durability
			//   guarantees to abort, but may be better to avoid long wait times
			//   on close.
			//
			delay := backoff(attempt, 100*time.Millisecond, 1*time.Second)
			ptw.w.withLogger(func(log Logger) {
				log.Printf("backing off %s writing %d messages to %s (partition: %d)", delay, len(batch.msgs), key.topic, key.partition)
			})
			time.Sleep(delay)
		}

		ptw.w.withLogger(func(log Logger) {
			log.Printf("writing %d messages to %s (partition: %d)", len(batch.msgs), key.topic, key.partition)
		})

		start := time.Now()
		res, err = ptw.w.produce(key, batch)

		stats.writes.observe(1)
		stats.messages.observe(int64(len(batch.msgs)))
		stats.bytes.observe(batch.bytes)
		// stats.writeTime used to report the duration of WriteMessages, but the
		// implementation was broken and reporting values in the nanoseconds
		// range. In kafka-go 0.4, we recylced this value to instead report the
		// duration of produce requests, and changed the stats.waitTime value to
		// report the time that kafka has throttled the requests for.
		stats.writeTime.observe(int64(time.Since(start)))

		if res != nil {
			err = res.Error
			stats.waitTime.observe(int64(res.Throttle))
		}

		if err == nil {
			break
		}

		stats.errors.observe(1)

		ptw.w.withErrorLogger(func(log Logger) {
			log.Printf("error writing messages to %s (partition %d): %s", key.topic, key.partition, err)
		})

		if !isTemporary(err) && !isTransientNetworkError(err) {
			break
		}
	}

	if res != nil {
		for i := range batch.msgs {
			m := &batch.msgs[i]
			m.Topic = key.topic
			m.Partition = int(key.partition)
			m.Offset = res.BaseOffset + int64(i)

			if m.Time.IsZero() {
				m.Time = res.LogAppendTime
			}
		}
	}

	if ptw.w.Completion != nil {
		ptw.w.Completion(batch.msgs, err)
	}

	batch.complete(err)
}

func (ptw *partitionWriter) close() {
	ptw.mutex.Lock()
	defer ptw.mutex.Unlock()

	if ptw.currBatch != nil {
		batch := ptw.currBatch
		ptw.queue.Put(batch)
		ptw.currBatch = nil
		batch.trigger()
	}

	ptw.queue.Close()
}

type writeBatch struct {
	time  time.Time
	msgs  []Message
	size  int
	bytes int64
	ready chan struct{}
	done  chan struct{}
	timer *time.Timer
	err   error // result of the batch completion
}

func newWriteBatch(now time.Time, timeout time.Duration) *writeBatch {
	return &writeBatch{
		time:  now,
		ready: make(chan struct{}),
		done:  make(chan struct{}),
		timer: time.NewTimer(timeout),
	}
}

func (b *writeBatch) add(msg Message, maxSize int, maxBytes int64) bool {
	bytes := int64(msg.size())

	if b.size > 0 && (b.bytes+bytes) > maxBytes {
		return false
	}

	if cap(b.msgs) == 0 {
		b.msgs = make([]Message, 0, maxSize)
	}

	b.msgs = append(b.msgs, msg)
	b.size++
	b.bytes += bytes
	return true
}

func (b *writeBatch) full(maxSize int, maxBytes int64) bool {
	return b.size >= maxSize || b.bytes >= maxBytes
}

func (b *writeBatch) trigger() {
	close(b.ready)
}

func (b *writeBatch) complete(err error) {
	b.err = err
	close(b.done)
}

type writerRecords struct {
	msgs   []Message
	index  int
	record Record
	key    bytesReadCloser
	value  bytesReadCloser
}

func (r *writerRecords) ReadRecord() (*Record, error) {
	if r.index >= 0 && r.index < len(r.msgs) {
		m := &r.msgs[r.index]
		r.index++
		r.record = Record{
			Time:    m.Time,
			Headers: m.Headers,
		}
		if m.Key != nil {
			r.key.Reset(m.Key)
			r.record.Key = &r.key
		}
		if m.Value != nil {
			r.value.Reset(m.Value)
			r.record.Value = &r.value
		}
		return &r.record, nil
	}
	return nil, io.EOF
}

type bytesReadCloser struct{ bytes.Reader }

func (*bytesReadCloser) Close() error { return nil }

// A cache of []int values passed to balancers of writers, used to amortize the
// heap allocation of the partition index lists.
//
// With hindsight, the use of `...int` to pass the partition list to Balancers
// was not the best design choice: kafka partition numbers are monotonically
// increasing, we could have simply passed the number of partitions instead.
// If we ever revisit this API, we can hopefully remove this cache.
var partitionsCache atomic.Value

func loadCachedPartitions(numPartitions int) []int {
	partitions, ok := partitionsCache.Load().([]int)
	if ok && len(partitions) >= numPartitions {
		return partitions[:numPartitions]
	}

	const alignment = 128
	n := ((numPartitions / alignment) + 1) * alignment

	partitions = make([]int, n)
	for i := range partitions {
		partitions[i] = i
	}

	partitionsCache.Store(partitions)
	return partitions[:numPartitions]
}
