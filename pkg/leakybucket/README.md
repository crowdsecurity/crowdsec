# Leakybuckets

## Concepts

Leakybuckets are used for decision-making. Under certain conditions,
enriched events are poured into buckets. When a bucket reaches its
threshold, it emits a new event (an *overflow*) and is then destroyed.

There are several bucket types, and we welcome contributions of new ones.

A single bucket configuration typically creates many bucket instances,
distinguished by a `stackkey`. Events with the same `stackkey` value are
poured into the same instance.

The main purpose is to detect clients that exceed a given rate of
attempts (SSH logins, HTTP auth failures, etc.). In practice, `stackkey`
is often `source_ip`.


## Standard leaky buckets

Default buckets have two main configuration options:

 - `capacity`: number of events the bucket can hold. When the capacity is
   reached and a new event is poured, the bucket overflows (emits an
   overflow event of type integer).

 - `leakspeed`: how long it takes for one event to leak out of the
   bucket. When an event leaks, it is removed from the bucket.

## Trigger

A Trigger has `capacity: 0`. Any poured event causes an overflow.

## Uniq

Uniq behaves like a standard bucket, except it enforces uniqueness:
a filter extracts a property from each event, and only one occurrence of
a given value is allowed. If the value is already present, the event is
ignored.

## Counter

A Counter has infinite `capacity` and infinite `leakspeed` (it never
overflows and never leaks). Instead, it emits an event after a fixed
`duration`.

## Bayesian


A Bayesian bucket runs Bayesian inference instead of counting events.
Each condition specifies likelihoods via `prob_given_benign` and
`prob_given_evil`. The bucket evaluates events until the posterior
exceeds `bayesian_threshold` (overflow) or until `leakspeed` expires.

## Configuration

### Common fields

- `type` (required): one of `"leaky"`, `"trigger"`, `"uniq"`, `"counter"`.

- `name` (required): tags events emitted by this bucket. Any value is accepted.

- `filter` (required): expression evaluated to decide whether an event
  matches. Must return a boolean. Expression language: <https://github.com/antonmedv/expr>.

- `stackkey` (required): selects the bucket instance to pour into. When a
  new `stackkey` value is seen, a new bucket instance is created.

- `on_overflow` (optional): action when the bucket overflows. Currently:
  `"ban,1h"`, `"Reprocess"`, `"Delete"`.
  `Reprocess` sends the emitted event back to the event pool to be
  matched again.

#### Standard bucket fields

- `capacity` (currently required): size of the bucket. When an event is
  poured into a full bucket, it overflows.

- `leakspeed`: duration parsed by `time.ParseDuration`:
  <https://pkg.go.dev/time#ParseDuration>. After each interval, an event leaks
  from the bucket.

#### Uniq fields

- `uniq_filter`: expr (in the Expression language) that must return a string.
  All strings returned for a given bucket instance must be unique; events generating
  a string that has already been seen are ignored.

#### Trigger fields

`capacity` and `leakspeed` do not apply.

#### Counter fields

- `duration`: how long the Counter exists before it emits its event and
  is destroyed. Parsed by `time.ParseDuration`.
  Counters are configured with infinite capacity (`capacity: -1`
  for now) and infinite leakspeed.

#### Bayesian fields

 * bayesian_prior: the prior to start with
 * bayesian_threshold: the threshold for the posterior to trigger the overflow.
 * bayesian_conditions: list of Bayesian conditions with likelihoods

Bayesian Conditions are built from:
 * condition: expr that must evaluate to true/false.
 * prob_given_evil: likelihood the condition holds given the IP is malicious.
 * prob_given_benign:  likelihood the condition holds given the IP is benign.
 * guillotine: if true, stop evaluating this condition after it becomes true
  once (useful for expensive conditions).


## Examples

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

# Implementation notes

The leaky-bucket pipeline is driven by `runPour()` in `cmd/crowdsec/pour.go`, which calls `Leaky.PourItemToHolders()`.

Buckets are managed by a `BucketStore`, which owns creation and lookup.
Each bucket is addressed by a deterministic key computed from the bucket’s configured filter and the event `stackkey`,
so the same (filter, stackkey) pair always maps to the same bucket instance.

The default implementation is the standard leaky bucket. Each bucket runs its own goroutine (`bucket.go`) responsible
for the bucket's lifecycle (processing poured events, timing/leaking, and cleanup).

The behavior of special buckets is wired via hooks during initialization in `manager_load.go`.
The bucket goroutine invokes these hooks at the appropriate time, typically when events are poured and/or when the bucket overflows.

