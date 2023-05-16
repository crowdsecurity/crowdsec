# kafka-go [![CircleCI](https://circleci.com/gh/segmentio/kafka-go.svg?style=shield)](https://circleci.com/gh/segmentio/kafka-go) [![Go Report Card](https://goreportcard.com/badge/github.com/segmentio/kafka-go)](https://goreportcard.com/report/github.com/segmentio/kafka-go) [![GoDoc](https://godoc.org/github.com/segmentio/kafka-go?status.svg)](https://godoc.org/github.com/segmentio/kafka-go)

## Motivations

We rely on both Go and Kafka a lot at Segment. Unfortunately, the state of the Go
client libraries for Kafka at the time of this writing was not ideal. The available
options were:

- [sarama](https://github.com/Shopify/sarama), which is by far the most popular
but is quite difficult to work with. It is poorly documented, the API exposes
low level concepts of the Kafka protocol, and it doesn't support recent Go features
like [contexts](https://golang.org/pkg/context/). It also passes all values as
pointers which causes large numbers of dynamic memory allocations, more frequent
garbage collections, and higher memory usage.

- [confluent-kafka-go](https://github.com/confluentinc/confluent-kafka-go) is a
cgo based wrapper around [librdkafka](https://github.com/edenhill/librdkafka),
which means it introduces a dependency to a C library on all Go code that uses
the package. It has much better documentation than sarama but still lacks support
for Go contexts.

- [goka](https://github.com/lovoo/goka) is a more recent Kafka client for Go
which focuses on a specific usage pattern. It provides abstractions for using Kafka
as a message passing bus between services rather than an ordered log of events, but
this is not the typical use case of Kafka for us at Segment. The package also
depends on sarama for all interactions with Kafka.

This is where `kafka-go` comes into play. It provides both low and high level
APIs for interacting with Kafka, mirroring concepts and implementing interfaces of
the Go standard library to make it easy to use and integrate with existing
software.

#### Note:

In order to better align with our newly adopted Code of Conduct, the kafka-go
project has renamed our default branch to `main`. For the full details of our
Code Of Conduct see [this](./CODE_OF_CONDUCT.md) document.

## Kafka versions

`kafka-go` is currently tested with Kafka versions 0.10.1.0 to 2.7.1.
While it should also be compatible with later versions, newer features available
in the Kafka API may not yet be implemented in the client.

## Go versions

`kafka-go` requires Go version 1.15 or later.

## Connection [![GoDoc](https://godoc.org/github.com/segmentio/kafka-go?status.svg)](https://godoc.org/github.com/segmentio/kafka-go#Conn)

The `Conn` type is the core of the `kafka-go` package. It wraps around a raw
network connection to expose a low-level API to a Kafka server.

Here are some examples showing typical use of a connection object:
```go
// to produce messages
topic := "my-topic"
partition := 0

conn, err := kafka.DialLeader(context.Background(), "tcp", "localhost:9092", topic, partition)
if err != nil {
    log.Fatal("failed to dial leader:", err)
}

conn.SetWriteDeadline(time.Now().Add(10*time.Second))
_, err = conn.WriteMessages(
    kafka.Message{Value: []byte("one!")},
    kafka.Message{Value: []byte("two!")},
    kafka.Message{Value: []byte("three!")},
)
if err != nil {
    log.Fatal("failed to write messages:", err)
}

if err := conn.Close(); err != nil {
    log.Fatal("failed to close writer:", err)
}
```
```go
// to consume messages
topic := "my-topic"
partition := 0

conn, err := kafka.DialLeader(context.Background(), "tcp", "localhost:9092", topic, partition)
if err != nil {
    log.Fatal("failed to dial leader:", err)
}

conn.SetReadDeadline(time.Now().Add(10*time.Second))
batch := conn.ReadBatch(10e3, 1e6) // fetch 10KB min, 1MB max

b := make([]byte, 10e3) // 10KB max per message
for {
    n, err := batch.Read(b)
    if err != nil {
        break
    }
    fmt.Println(string(b[:n]))
}

if err := batch.Close(); err != nil {
    log.Fatal("failed to close batch:", err)
}

if err := conn.Close(); err != nil {
    log.Fatal("failed to close connection:", err)
}
```

### To Create Topics
By default kafka has the `auto.create.topics.enable='true'` (`KAFKA_AUTO_CREATE_TOPICS_ENABLE='true'` in the wurstmeister/kafka kafka docker image). If this value is set to `'true'` then topics will be created as a side effect of `kafka.DialLeader` like so:
```go
// to create topics when auto.create.topics.enable='true'
conn, err := kafka.DialLeader(context.Background(), "tcp", "localhost:9092", "my-topic", 0)
if err != nil {
    panic(err.Error())
}
```

If `auto.create.topics.enable='false'` then you will need to create topics explicitly like so:
```go
// to create topics when auto.create.topics.enable='false'
topic := "my-topic"

conn, err := kafka.Dial("tcp", "localhost:9092")
if err != nil {
    panic(err.Error())
}
defer conn.Close()

controller, err := conn.Controller()
if err != nil {
    panic(err.Error())
}
var controllerConn *kafka.Conn
controllerConn, err = kafka.Dial("tcp", net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port)))
if err != nil {
    panic(err.Error())
}
defer controllerConn.Close()


topicConfigs := []kafka.TopicConfig{
    {
        Topic:             topic,
        NumPartitions:     1,
        ReplicationFactor: 1,
    },
}

err = controllerConn.CreateTopics(topicConfigs...)
if err != nil {
    panic(err.Error())
}
```

### To Connect To Leader Via a Non-leader Connection
```go
// to connect to the kafka leader via an existing non-leader connection rather than using DialLeader
conn, err := kafka.Dial("tcp", "localhost:9092")
if err != nil {
    panic(err.Error())
}
defer conn.Close()
controller, err := conn.Controller()
if err != nil {
    panic(err.Error())
}
var connLeader *kafka.Conn
connLeader, err = kafka.Dial("tcp", net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port)))
if err != nil {
    panic(err.Error())
}
defer connLeader.Close()
```

### To list topics
```go
conn, err := kafka.Dial("tcp", "localhost:9092")
if err != nil {
    panic(err.Error())
}
defer conn.Close()

partitions, err := conn.ReadPartitions()
if err != nil {
    panic(err.Error())
}

m := map[string]struct{}{}

for _, p := range partitions {
    m[p.Topic] = struct{}{}
}
for k := range m {
    fmt.Println(k)
}
```


Because it is low level, the `Conn` type turns out to be a great building block
for higher level abstractions, like the `Reader` for example.

## Reader [![GoDoc](https://godoc.org/github.com/segmentio/kafka-go?status.svg)](https://godoc.org/github.com/segmentio/kafka-go#Reader)

A `Reader` is another concept exposed by the `kafka-go` package, which intends
to make it simpler to implement the typical use case of consuming from a single
topic-partition pair.
A `Reader` also automatically handles reconnections and offset management, and
exposes an API that supports asynchronous cancellations and timeouts using Go
contexts.

Note that it is important to call `Close()` on a `Reader` when a process exits.
The kafka server needs a graceful disconnect to stop it from continuing to
attempt to send messages to the connected clients. The given example will not
call `Close()` if the process is terminated with SIGINT (ctrl-c at the shell) or
SIGTERM (as docker stop or a kubernetes restart does). This can result in a
delay when a new reader on the same topic connects (e.g. new process started
or new container running). Use a `signal.Notify` handler to close the reader on
process shutdown.

```go
// make a new reader that consumes from topic-A, partition 0, at offset 42
r := kafka.NewReader(kafka.ReaderConfig{
    Brokers:   []string{"localhost:9092","localhost:9093", "localhost:9094"},
    Topic:     "topic-A",
    Partition: 0,
    MinBytes:  10e3, // 10KB
    MaxBytes:  10e6, // 10MB
})
r.SetOffset(42)

for {
    m, err := r.ReadMessage(context.Background())
    if err != nil {
        break
    }
    fmt.Printf("message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))
}

if err := r.Close(); err != nil {
    log.Fatal("failed to close reader:", err)
}
```

### Consumer Groups

```kafka-go``` also supports Kafka consumer groups including broker managed offsets.
To enable consumer groups, simply specify the GroupID in the ReaderConfig.

ReadMessage automatically commits offsets when using consumer groups.

```go
// make a new reader that consumes from topic-A
r := kafka.NewReader(kafka.ReaderConfig{
    Brokers:   []string{"localhost:9092", "localhost:9093", "localhost:9094"},
    GroupID:   "consumer-group-id",
    Topic:     "topic-A",
    MinBytes:  10e3, // 10KB
    MaxBytes:  10e6, // 10MB
})

for {
    m, err := r.ReadMessage(context.Background())
    if err != nil {
        break
    }
    fmt.Printf("message at topic/partition/offset %v/%v/%v: %s = %s\n", m.Topic, m.Partition, m.Offset, string(m.Key), string(m.Value))
}

if err := r.Close(); err != nil {
    log.Fatal("failed to close reader:", err)
}
```

There are a number of limitations when using consumer groups:

* ```(*Reader).SetOffset``` will return an error when GroupID is set
* ```(*Reader).Offset``` will always return ```-1``` when GroupID is set
* ```(*Reader).Lag``` will always return ```-1``` when GroupID is set
* ```(*Reader).ReadLag``` will return an error when GroupID is set
* ```(*Reader).Stats``` will return a partition of ```-1``` when GroupID is set

### Explicit Commits

```kafka-go``` also supports explicit commits.  Instead of calling ```ReadMessage```,
call ```FetchMessage``` followed by ```CommitMessages```.

```go
ctx := context.Background()
for {
    m, err := r.FetchMessage(ctx)
    if err != nil {
        break
    }
    fmt.Printf("message at topic/partition/offset %v/%v/%v: %s = %s\n", m.Topic, m.Partition, m.Offset, string(m.Key), string(m.Value))
    if err := r.CommitMessages(ctx, m); err != nil {
        log.Fatal("failed to commit messages:", err)
    }
}
```

When committing messages in consumer groups, the message with the highest offset
for a given topic/partition determines the value of the committed offset for
that partition. For example, if messages at offset 1, 2, and 3 of a single
partition were retrieved by call to `FetchMessage`, calling `CommitMessages`
with message offset 3 will also result in committing the messages at offsets 1
and 2 for that partition.

### Managing Commits

By default, CommitMessages will synchronously commit offsets to Kafka.  For
improved performance, you can instead periodically commit offsets to Kafka
by setting CommitInterval on the ReaderConfig.


```go
// make a new reader that consumes from topic-A
r := kafka.NewReader(kafka.ReaderConfig{
    Brokers:        []string{"localhost:9092", "localhost:9093", "localhost:9094"},
    GroupID:        "consumer-group-id",
    Topic:          "topic-A",
    MinBytes:       10e3, // 10KB
    MaxBytes:       10e6, // 10MB
    CommitInterval: time.Second, // flushes commits to Kafka every second
})
```

## Writer [![GoDoc](https://godoc.org/github.com/segmentio/kafka-go?status.svg)](https://godoc.org/github.com/segmentio/kafka-go#Writer)

To produce messages to Kafka, a program may use the low-level `Conn` API, but
the package also provides a higher level `Writer` type which is more appropriate
to use in most cases as it provides additional features:

- Automatic retries and reconnections on errors.
- Configurable distribution of messages across available partitions.
- Synchronous or asynchronous writes of messages to Kafka.
- Asynchronous cancellation using contexts.
- Flushing of pending messages on close to support graceful shutdowns.
- Creation of a missing topic before publishing a message. *Note!* it was the default behaviour up to the version `v0.4.30`.

```go
// make a writer that produces to topic-A, using the least-bytes distribution
w := &kafka.Writer{
	Addr:     kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
	Topic:   "topic-A",
	Balancer: &kafka.LeastBytes{},
}

err := w.WriteMessages(context.Background(),
	kafka.Message{
		Key:   []byte("Key-A"),
		Value: []byte("Hello World!"),
	},
	kafka.Message{
		Key:   []byte("Key-B"),
		Value: []byte("One!"),
	},
	kafka.Message{
		Key:   []byte("Key-C"),
		Value: []byte("Two!"),
	},
)
if err != nil {
    log.Fatal("failed to write messages:", err)
}

if err := w.Close(); err != nil {
    log.Fatal("failed to close writer:", err)
}
```

### Missing topic creation before publication

```go
// Make a writer that publishes messages to topic-A.
// The topic will be created if it is missing.
w := &Writer{
    Addr:                   kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
    Topic:                  "topic-A",
    AllowAutoTopicCreation: true,
}

messages := []kafka.Message{
    {
        Key:   []byte("Key-A"),
        Value: []byte("Hello World!"),
    },
    {
        Key:   []byte("Key-B"),
        Value: []byte("One!"),
    },
    {
        Key:   []byte("Key-C"),
        Value: []byte("Two!"),
    },
}

var err error
const retries = 3
for i := 0; i < retries; i++ {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // attempt to create topic prior to publishing the message
    err = w.WriteMessages(ctx, messages...)
    if errors.Is(err, LeaderNotAvailable) || errors.Is(err, context.DeadlineExceeded) {
        time.Sleep(time.Millisecond * 250)
        continue
    }

    if err != nil {
        log.Fatalf("unexpected error %v", err)
    }
}

if err := w.Close(); err != nil {
    log.Fatal("failed to close writer:", err)
}
```

### Writing to multiple topics

Normally, the `WriterConfig.Topic` is used to initialize a single-topic writer.
By excluding that particular configuration, you are given the ability to define
the topic on a per-message basis by setting `Message.Topic`.

```go
w := &kafka.Writer{
	Addr:     kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
    // NOTE: When Topic is not defined here, each Message must define it instead.
	Balancer: &kafka.LeastBytes{},
}

err := w.WriteMessages(context.Background(),
    // NOTE: Each Message has Topic defined, otherwise an error is returned.
	kafka.Message{
        Topic: "topic-A",
		Key:   []byte("Key-A"),
		Value: []byte("Hello World!"),
	},
	kafka.Message{
        Topic: "topic-B",
		Key:   []byte("Key-B"),
		Value: []byte("One!"),
	},
	kafka.Message{
        Topic: "topic-C",
		Key:   []byte("Key-C"),
		Value: []byte("Two!"),
	},
)
if err != nil {
    log.Fatal("failed to write messages:", err)
}

if err := w.Close(); err != nil {
    log.Fatal("failed to close writer:", err)
}
```

**NOTE:** These 2 patterns are mutually exclusive, if you set `Writer.Topic`,
you must not also explicitly define `Message.Topic` on the messages you are
writing. The opposite applies when you do not define a topic for the writer.
The `Writer` will return an error if it detects this ambiguity.

### Compatibility with other clients

#### Sarama

If you're switching from Sarama and need/want to use the same algorithm for message partitioning, you can either use 
the `kafka.Hash` balancer or the `kafka.ReferenceHash` balancer:
* `kafka.Hash` = `sarama.NewHashPartitioner`
* `kafka.ReferenceHash` = `sarama.NewReferenceHashPartitioner`

The `kafka.Hash` and `kafka.ReferenceHash` balancers would route messages to the same partitions that the two 
aforementioned Sarama partitioners would route them to.

```go
w := &kafka.Writer{
	Addr:     kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
	Topic:    "topic-A",
	Balancer: &kafka.Hash{},
}
```

#### librdkafka and confluent-kafka-go

Use the ```kafka.CRC32Balancer``` balancer to get the same behaviour as librdkafka's
default ```consistent_random``` partition strategy.

```go
w := &kafka.Writer{
	Addr:     kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
	Topic:    "topic-A",
	Balancer: kafka.CRC32Balancer{},
}
```

#### Java

Use the ```kafka.Murmur2Balancer``` balancer to get the same behaviour as the canonical
Java client's default partitioner.  Note: the Java class allows you to directly specify
the partition which is not permitted.

```go
w := &kafka.Writer{
	Addr:     kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
	Topic:    "topic-A",
	Balancer: kafka.Murmur2Balancer{},
}
```

### Compression

Compression can be enabled on the `Writer` by setting the `Compression` field:

```go
w := &kafka.Writer{
	Addr:        kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
	Topic:       "topic-A",
	Compression: kafka.Snappy,
}
```

The `Reader` will by determine if the consumed messages are compressed by
examining the message attributes.  However, the package(s) for all expected
codecs must be imported so that they get loaded correctly.

_Note: in versions prior to 0.4 programs had to import compression packages to
install codecs and support reading compressed messages from kafka. This is no
longer the case and import of the compression packages are now no-ops._

## TLS Support

For a bare bones Conn type or in the Reader/Writer configs you can specify a dialer option for TLS support. If the TLS field is nil, it will not connect with TLS.
*Note:* Connecting to a Kafka cluster with TLS enabled without configuring TLS on the Conn/Reader/Writer can manifest in opaque io.ErrUnexpectedEOF errors.


### Connection

```go
dialer := &kafka.Dialer{
    Timeout:   10 * time.Second,
    DualStack: true,
    TLS:       &tls.Config{...tls config...},
}

conn, err := dialer.DialContext(ctx, "tcp", "localhost:9093")
```

### Reader

```go
dialer := &kafka.Dialer{
    Timeout:   10 * time.Second,
    DualStack: true,
    TLS:       &tls.Config{...tls config...},
}

r := kafka.NewReader(kafka.ReaderConfig{
    Brokers:        []string{"localhost:9092", "localhost:9093", "localhost:9094"},
    GroupID:        "consumer-group-id",
    Topic:          "topic-A",
    Dialer:         dialer,
})
```

### Writer


Direct Writer creation

```go
w := kafka.Writer{
    Addr: kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"), 
    Topic:   "topic-A",
    Balancer: &kafka.Hash{},
    Transport: &kafka.Transport{
        TLS: &tls.Config{},
      },
    }
```

Using `kafka.NewWriter`

```go
dialer := &kafka.Dialer{
    Timeout:   10 * time.Second,
    DualStack: true,
    TLS:       &tls.Config{...tls config...},
}

w := kafka.NewWriter(kafka.WriterConfig{
	Brokers: []string{"localhost:9092", "localhost:9093", "localhost:9094"},
	Topic:   "topic-A",
	Balancer: &kafka.Hash{},
	Dialer:   dialer,
})
```
Note that `kafka.NewWriter` and `kafka.WriterConfig` are deprecated and will be removed in a future release.

## SASL Support

You can specify an option on the `Dialer` to use SASL authentication. The `Dialer` can be used directly to open a `Conn` or it can be passed to a `Reader` or `Writer` via their respective configs. If the `SASLMechanism` field is `nil`, it will not authenticate with SASL.

### SASL Authentication Types

#### [Plain](https://godoc.org/github.com/segmentio/kafka-go/sasl/plain#Mechanism)
```go
mechanism := plain.Mechanism{
    Username: "username",
    Password: "password",
}
```

#### [SCRAM](https://godoc.org/github.com/segmentio/kafka-go/sasl/scram#Mechanism)
```go
mechanism, err := scram.Mechanism(scram.SHA512, "username", "password")
if err != nil {
    panic(err)
}
```

### Connection

```go
mechanism, err := scram.Mechanism(scram.SHA512, "username", "password")
if err != nil {
    panic(err)
}

dialer := &kafka.Dialer{
    Timeout:       10 * time.Second,
    DualStack:     true,
    SASLMechanism: mechanism,
}

conn, err := dialer.DialContext(ctx, "tcp", "localhost:9093")
```


### Reader

```go
mechanism, err := scram.Mechanism(scram.SHA512, "username", "password")
if err != nil {
    panic(err)
}

dialer := &kafka.Dialer{
    Timeout:       10 * time.Second,
    DualStack:     true,
    SASLMechanism: mechanism,
}

r := kafka.NewReader(kafka.ReaderConfig{
    Brokers:        []string{"localhost:9092","localhost:9093", "localhost:9094"},
    GroupID:        "consumer-group-id",
    Topic:          "topic-A",
    Dialer:         dialer,
})
```

### Writer

```go
mechanism, err := scram.Mechanism(scram.SHA512, "username", "password")
if err != nil {
    panic(err)
}

// Transports are responsible for managing connection pools and other resources,
// it's generally best to create a few of these and share them across your
// application.
sharedTransport := &kafka.Transport{
    SASL: mechanism,
}

w := kafka.Writer{
	Addr:      kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
	Topic:     "topic-A",
	Balancer:  &kafka.Hash{},
	Transport: sharedTransport,
}
```

### Client

```go
mechanism, err := scram.Mechanism(scram.SHA512, "username", "password")
if err != nil {
    panic(err)
}

// Transports are responsible for managing connection pools and other resources,
// it's generally best to create a few of these and share them across your
// application.
sharedTransport := &kafka.Transport{
    SASL: mechanism,
}

client := &kafka.Client{
    Addr:      kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
    Timeout:   10 * time.Second,
    Transport: sharedTransport,
}
```

#### Reading all messages within a time range

```go
startTime := time.Now().Add(-time.Hour)
endTime := time.Now()
batchSize := int(10e6) // 10MB

r := kafka.NewReader(kafka.ReaderConfig{
    Brokers:   []string{"localhost:9092", "localhost:9093", "localhost:9094"},
    Topic:     "my-topic1",
    Partition: 0,
    MinBytes:  batchSize,
    MaxBytes:  batchSize,
})

r.SetOffsetAt(context.Background(), startTime)

for {
    m, err := r.ReadMessage(context.Background())

    if err != nil {
        break
    }
    if m.Time.After(endTime) {
        break
    }
    // TODO: process message
    fmt.Printf("message at offset %d: %s = %s\n", m.Offset, string(m.Key), string(m.Value))
}

if err := r.Close(); err != nil {
    log.Fatal("failed to close reader:", err)
}
```


## Logging

For visiblity into the operations of the Reader/Writer types, configure a logger on creation.


### Reader

```go
func logf(msg string, a ...interface{}) {
	fmt.Printf(msg, a...)
	fmt.Println()
}

r := kafka.NewReader(kafka.ReaderConfig{
	Brokers:     []string{"localhost:9092", "localhost:9093", "localhost:9094"},
	Topic:       "my-topic1",
	Partition:   0,
	Logger:      kafka.LoggerFunc(logf),
	ErrorLogger: kafka.LoggerFunc(logf),
})
```

### Writer

```go
func logf(msg string, a ...interface{}) {
	fmt.Printf(msg, a...)
	fmt.Println()
}

w := &kafka.Writer{
	Addr:        kafka.TCP("localhost:9092"),
	Topic:       "topic",
	Logger:      kafka.LoggerFunc(logf),
	ErrorLogger: kafka.LoggerFunc(logf),
}
```



## Testing

Subtle behavior changes in later Kafka versions have caused some historical tests to break, if you are running against Kafka 2.3.1 or later, exporting the `KAFKA_SKIP_NETTEST=1` environment variables will skip those tests.

Run Kafka locally in docker

```bash
docker-compose up -d
```

Run tests

```bash
KAFKA_VERSION=2.3.1 \
  KAFKA_SKIP_NETTEST=1 \
  go test -race ./...
```
