# Leakybuckets

## Bucket concepts

Leakybucket is used for decision making. Under certain conditions
enriched events are poured in these buckets. When these buckets are
full, we raise a new event. After this event is raised the bucket is
destroyed. There are many types of buckets, and we welcome any new
useful design of buckets.

Usually the bucket configuration generates the creation of many
buckets. They are differenciated by a field called stackkey. When two
events arrives with the same stackkey they go in the same matching
bucket.

The very purpose of these buckets is to detect clients that exceed a
certain rate of attemps to do something (ssh connection, http
authentication failure, etc...). Thus, the most use stackkey field is
often the source_ip.

## Standard leaky buckets

Default buckets have two main configuration options:
 * capacity: number of events the bucket can hold. When the capacity
   is reached and a new event is poured, a new event is raised. We
   call this type of event overflow. This is an int.
 * leakspeed: duration needed for an event to leak. When an event
   leaks, it disappear from the bucket.

## Trigger

It's a special type of bucket with a zero capacity. Thus, when an
event is poured in a trigger, it always raises an overflow.

## Uniq

It's a bucket working as the standard leaky bucket except for one
thing: a filter returns a property for each event and only one
occurence of this property is allowed in the bucket, thus the bucket
is called uniq.

## Counter

It's a special type of bucket with an infinite capacity and an
infinite leakspeed (it never overflows, neither leaks). Nevertheless,
the event is raised after a fixed duration. The option is called
duration.

## Available configuration options for buckets

### Fields for standard buckets

* type: mandatory field. Must be one of "leaky", "trigger", "uniq" or
  "counter"
* name: mandatory field, but the value is totally open. Nevertheless
  this value will tag the events raised by the bucket.
* filter: mandatory field. It's a filter that is run when the decision
  to make an event match the bucket or not. The filter have to return
  a boolean. As a filter implementation we use
  https://github.com/antonmedv/expr
* capacity: [mandatory for now, shouldn't be mandatory in the final
  version] it's the size of the bucket. When pouring in a bucket
  already with size events, it overflows.
* leakspeed: leakspeed is a time duration (has to be parseable by
  https://golang.org/pkg/time/#ParseDuration). After each interval an
  event is leaked from the bucket.
* stackkey: mandatory field. This field is used to differenciate on
  which bucket ongoing events will be poured. When an unknows stackkey
  is seen in an event a new bucekt is created.
* on_overflow: optional field, that tells the what to do when the
  bucket is returning the overflow event. As of today, the possibility
  are these: "ban,1h", "Reprocess", "Delete".
  Reprocess is used to send the raised event back in the event pool to
  be matched agains buckets

### Fields for special buckets

#### Uniq

Uniq has an extra field uniq_filter which is too use the filter
implementation from https://github.com/antonmedv/expr. The filter must
return a string. All strins returned by this filter in the same
buckets have to be different. Thus, if a string is seen twice it is
dismissed.

#### Trigger

Capacity and leakspeed are not relevant for this kind of bucket.

#### Counter

It's a special kind of bucket that raise an event and is destroyed
after a fixed duration. The configuration field used is duration and
must be parseable by https://golang.org/pkg/time/#ParseDuration.
Nevertheless, this kind of bucket is often used with an infinite
leakspeed and an infinite capacity [capacity set to -1 for now].


## Add exemples here

```
# ssh bruteforce
- type: leaky
  name: ssh_bruteforce
  filter: "Meta.log_type == 'ssh_failed-auth'"
  leakspeed: "10s"
  capacity: 5
  stackkey: "source_ip"
  on_overflow: ban,1h

# reporting of src_ip,dest_port seen
- type: counter
  name: counter
  filter: "Meta.service == 'tcp' && Event.new_connection == 'true'"
  distinct: "Meta.source_ip + ':' + Meta.dest_port"
  duration: 5m
  capacity: -1

- type: trigger
  name: "New connection"
  filter: "Meta.service == 'tcp' && Event.new_connection == 'true'"
  on_overflow: Reprocess
```

# Note on leakybuckets implementation

[This is not dry enough to have many details here, but:]

The bucket code is triggered by `InfiniBucketify` in main.go.
There's one struct called buckets which is for now a
`map[string]interface{}` that holds all buckets. The key of this map
is derivated from the filter configured for the bucket and its
stackkey. This looks like complicated, but in fact it allows us to use
only one structs. This is done in buckets.go.

On top of that the implementation define only the standard leaky
bucket. A goroutine is launched for every buckets (bucket.go). This
goroutine manages the life of the bucket.

For special buckets, hooks are defined at initialization time in
manager.go. Hooks are called when relevant by the bucket gorourine
when events are poured and/or when bucket overflows.