# Leakybuckets

## Bucket concepts

The Leakybucket is used for decision making. Under certain conditions,
enriched events are poured into these buckets. When these buckets are
full, we raise a new event. After this event is raised the bucket is
destroyed. There are many types of buckets, and we welcome any new
useful design of buckets.

Usually, the bucket configuration generates the creation of many
buckets. They are differentiated by a field called stackkey. When two
events arrive with the same stackkey they go in the same matching
bucket.

The very purpose of these buckets is to detect clients that exceed a
certain rate of attempts to do something (ssh connection, http
authentication failure, etc...). Thus, the most used stackkey field is
often the source_ip.

## Standard leaky buckets

Default buckets have two main configuration options:

 * capacity: number of events the bucket can hold. When the capacity
   is reached and a new event is poured, a new event is raised. We
   call this type of event overflow. This is an int.

 * leakspeed: duration needed for an event to leak. When an event
   leaks, it disappears from the bucket.

## Trigger

A Trigger is a special type of bucket with a capacity of zero. Thus, when an
event is poured into a trigger, it always raises an overflow.

## Uniq

A Uniq is a bucket working like the standard leaky bucket except for one
thing: a filter returns a property for each event and only one
occurrence of this property is allowed in the bucket, thus the bucket
is called uniq.

## Counter

A Counter is a special type of bucket with an infinite capacity and an
infinite leakspeed (it never overflows, nor leaks). Nevertheless,
the event is raised after a fixed duration. The option is called
duration.

## Bayesian

A Bayesian is a special bucket that runs bayesian inference instead of 
counting events. Each event must have its likelihoods specified in the
yaml file under `prob_given_benign` and `prob_given_evil`. The bucket
will continue evaluating events until the posterior goes above the 
threshold (triggering the overflow) or the duration (specified by leakspeed)
expires.

## Available configuration options for buckets

### Fields for standard buckets

* type: mandatory field. Must be one of "leaky", "trigger", "uniq" or
  "counter"

* name: mandatory field, but the value is totally open. Nevertheless,
  this value will tag the events raised by the bucket.

* filter: mandatory field. It's a filter that is run to decide whether
  an event matches the bucket or not. The filter has to return
  a boolean. As a filter implementation we use
  https://github.com/antonmedv/expr

* capacity: [mandatory for now, shouldn't be mandatory in the final
  version] it's the size of the bucket. When pouring in a bucket
  already with size events, it overflows.

* leakspeed: leakspeed is a time duration (it has to be parsed by
  https://golang.org/pkg/time/#ParseDuration). After each interval, an
  event is leaked from the bucket.

* stackkey: mandatory field. This field is used to differentiate on
  which instance of the bucket the matching events will be poured.
  When an unknown stackkey is seen in an event, a new bucket is created.

* on_overflow: optional field, that tells what to do when the
  bucket is returning the overflow event. As of today, the possibilities
  are "ban,1h", "Reprocess" or "Delete".
  Reprocess is used to send the raised event back to the event pool to
  be matched against buckets

### Fields for special buckets

#### Uniq

 * uniq_filter: an expression that must comply with the syntax defined
   in https://github.com/antonmedv/expr and must return a string.
   All strings returned by this filter in the same buckets have to be different.
   Thus if a string is seen twice, the event is dismissed.

#### Trigger

Capacity and leakspeed are not relevant for this kind of bucket.

#### Counter

 * duration: the Counter will be destroyed after this interval
   has elapsed since its creation. The duration must be parsed
   by https://golang.org/pkg/time/#ParseDuration.
   Nevertheless, this kind of bucket is often used with an infinite
   leakspeed and an infinite capacity [capacity set to -1 for now].

#### Bayesian

 * bayesian_prior: The prior to start with
 * bayesian_threshold: The threshold for the posterior to trigger the overflow.
 * bayesian_conditions: List of Bayesian conditions with likelihoods

Bayesian Conditions are built from:
 * condition: The expr for this specific condition to be true
 * prob_given_evil: The likelihood an IP satisfies the condition given the fact
   that it is a maliscious IP
 * prob_given_benign: The likelihood an IP satisfies the condition given the fact
   that it is a benign IP
 * guillotine: Bool to stop the condition from getting evaluated if it has
   evaluated to true once. This should be used if evaluating the condition is 
   computationally expensive. 


## Add examples here

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

The bucket code is triggered by runPour in pour.go, by calling the `leaky.PourItemToHolders` function.
There is one struct called buckets which is for now a
`map[string]interface{}` that holds all buckets. The key of this map
is derived from the filter configured for the bucket and its
stackkey. This looks complicated, but it allows us to use
only one struct. This is done in buckets.go.

On top of that the implementation defines only the standard leaky
bucket. A goroutine is launched for every bucket (`bucket.go`). This
goroutine manages the life of the bucket.

For special buckets, hooks are defined at initialization time in
manager.go. Hooks are called when relevant by the bucket goroutine
when events are poured and/or when a bucket overflows.
