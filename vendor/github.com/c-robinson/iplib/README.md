# IPLib 
[![Documentation](https://godoc.org/github.com/c-robinson/iplib?status.svg)](http://godoc.org/github.com/c-robinson/iplib)
[![CircleCI](https://circleci.com/gh/c-robinson/iplib/tree/main.svg?style=svg)](https://circleci.com/gh/c-robinson/iplib/tree/main)
[![Go Report Card](https://goreportcard.com/badge/github.com/c-robinson/iplib)](https://goreportcard.com/report/github.com/c-robinson/iplib)
[![Coverage Status](https://coveralls.io/repos/github/c-robinson/iplib/badge.svg?branch=main)](https://coveralls.io/github/c-robinson/iplib?branch=main)

I really enjoy Python's [ipaddress](https://docs.python.org/3/library/ipaddress.html)
library and Ruby's [ipaddr](https://ruby-doc.org/stdlib-2.5.1/libdoc/ipaddr/rdoc/IPAddr.html),
I think you can write a lot of neat software if some of the little problems
around manipulating IP addresses and netblocks are taken care of for you, so I
set out to write something like them for my language of choice, Go. This is
what I've come up with.

[IPLib](http://godoc.org/github.com/c-robinson/iplib) is a hopefully useful,
aspirationally full-featured library built around and on top of the address
primitives found in the [net](https://golang.org/pkg/net/) package, it seeks
to make them more accessible and easier to manipulate. 

It includes:

##### net.IP tools

Some simple tools for performing common tasks against IP objects:

- compare two addresses
- get the delta between two addresses
- sort
- decrement or increment addresses
- print addresses as binary or hexadecimal strings, or print their addr.ARPA
  DNS name
- print v6 in fully expanded form
- convert between net.IP and integer values
- get the version of a v4 address or force a IPv4-mapped IPv6address to be a 
  v4 address

##### iplib.Net

An enhancement of `net.IPNet`, `iplib.Net` is an interface with two, version-
specific implementations providing features such as:

- retrieve the first and last usable address
- retrieve the wildcard mask
- enumerate all or part of a netblock to `[]net.IP`
- decrement or increment addresses within the boundaries of the netblock
- return the supernet of a netblock
- allocate subnets within the netblock
- return next- or previous-adjacent netblocks

##### Net4 and Net6 implementations of Net

The two address versions behave differently in both large and subtle ways,
and the version-specific implementations seek to account for this. For example
the Net4 implementation omits the network and broadcast addresses from
consideration during enumeration; while the Net6 implementation introduces the
concept of a HostMask, which blocks usable addresses off from the right in the
same way that a netmask constrains them from the left

Additional version-specific considerations described in the [Net4](#using-iplibnet4)
and [Net6](#using-iplibnet6) sections below.

## Sub-modules

- [iana](https://github.com/c-robinson/iplib/tree/main/iana) - a module for referencing 
  IP netblocks against the [Internet Assigned Numbers Authority's](https://www.iana.org/)
  Special IP Address Registry
- [iid](https://github.com/c-robinson/iplib/tree/main/iid) - a module for
  generating and validating IPv6 Interface Identifiers, including [RFC4291](https://tools.ietf.org/html/rfc4291)
  modified EUI64 and [RFC7217](https://tools.ietf.org/html/rfc7217)
  Semantically Opaque addresses

## Installing

```sh
go get -u github.com/c-robinson/iplib
```

## Using iplib

There are a series of functions for working with v4 or v6 `net.IP` objects:

```go
package main

import (
	"fmt"
	"net"
	"sort"
	
	"github.com/c-robinson/iplib"
)


func main() {
	ipa := net.ParseIP("192.168.1.1")
	ipb := iplib.IncrementIPBy(ipa, 15)      // ipb is 192.168.1.16
	ipc := iplib.NextIP(ipa)                 // ipc is 192.168.1.2

	fmt.Println(iplib.CompareIPs(ipa, ipb))  // -1
    
	fmt.Println(iplib.DeltaIP(ipa, ipb))     // 15
    
	fmt.Println(iplib.IPToHexString(ipc))    // "c0a80102"

	iplist := []net.IP{ ipb, ipc, ipa }
	sort.Sort(iplib.ByIP(iplist))            // []net.IP{ipa, ipc, ipb}

	fmt.Println(iplib.IP4ToUint32(ipa))      // 3232235777
	fmt.Println(iplib.IPToBinaryString(ipa)) // 11000000.10101000.00000001.00000001
	fmt.Println(iplib.IP4ToARPA(ipa))        // 1.1.168.192.in-addr.arpa
}
```

Addresses that require or return a count default to using `uint32`, which is
sufficient for working with the entire IPv4 space. As a rule these functions
are just lowest-common wrappers around IPv4- or IPv6-specific functions. The
IPv6-specific variants use `big.Int` so they can access the entire v6 space.

## The iplib.Net interface

`Net` describes an `iplib.Net` object, the exposed functions are those that 
are required for comparison, sorting, generic initialization and for ancillary 
functions such as those found in this package's submodules.

## Using iplib.Net4

`Net4` represents an IPv4 network. Since the first and last addresses of a v4
network are typically not allocated for use these will be omitted by
`Enumerate()`, `NextIP()` and `PreviousIP()`; they wont show up in `Count()`;
and `FirstAddress()` and `LastAddress()` show the 2nd and 2nd-to-the-last
addresses respectively. The v4-specific method `NetworkAddress()` returns the
first address, while `BroadcastAddress()` returns the last. There is an
exception made for `Net4` networks defined with a 31-bit netmask, since these
are assumed to be for [RFC3021](https://datatracker.ietf.org/doc/html/rfc3021)
point-to-point links.

Additionally `Net4` contains a `Wildcard()` method which will return the
network's [wildcard address](https://en.wikipedia.org/wiki/Wildcard_mask).

```go
n := iplib.NewNet4(net.ParseIP("192.168.0.0"), 16)
fmt.Println(n.Count())            // 65534 (note: not 65536)
fmt.Println(n.Enumerate(2, 1024)) // [192.168.4.1 192.168.4.2]
fmt.Println(n.IP())               // 192.168.0.0
fmt.Println(n.FirstAddress())     // 192.168.0.1
fmt.Println(n.LastAddress())      // 192.168.255.254
fmt.Println(n.BroadcastAddress()) // 192.168.255.255
fmt.Println(n.Wildcard())         // 0000ffff
fmt.Println(n.Subnet(0))          // [192.168.0.0/17 192.168.128.0/17] <nil>
fmt.Println(n.Supernet(0))        // 192.168.0.0/15 <nil>
```

## Using iplib.Net6

`Net6` represents and IPv6 network. In some ways v6 is simpler than v4, as
it does away with the special behavior of addresses at the front and back of
the netblock. For IPv6 the primary problem is the sheer size of the thing:
there are 2^128th addresses in IPv6, which translates to 340 undecillion!

```go
n := iplib.NewNet6(net.ParseIP("2001:db8::"), 56, 0)
fmt.Println(n.Count())                  // 4722366482869645213696
fmt.Println(n.Enumerate(2, 1024))       // [2001:db8::400 2001:db8::401]
fmt.Println(n.FirstAddress())           // 2001:db8::
fmt.Println(n.NextIP(n.FirstAddress())) // 2001:db8::1 <nil>
fmt.Println(n.LastAddress())            // 2001:db8:0:ff:ffff:ffff:ffff:ffff
fmt.Println(n.Subnet(0, 0))             // [2001:db8::/57 2001:db8:0:80::/57] <nil>
fmt.Println(n.Supernet(0, 0))           // 2001:db8::/55 <nil>
```

### HostMasks with Net6

To manage the address space, `Net6` introduces `HostMask`. This optional
constraint can be used to block addresses on the right-side of a netblock
somewhat like Netmasks do on the left. `Hostmask` must be specified at
initialization time and, if set, will affect the behavior of `Count()`, 
`Enumerate()`, `LastAddress()`, `NextIP()` and `PreviousIP()`. `Subnet()` and
`Supernet()` generate objects that inherit the hostmask of their parent, while
a hostmask must be specified for `NextNet()` and `PreviousNet()`.

```go
// this is the same as the previous example, except with a hostmask set
n := NewNet6(net.ParseIP("2001:db8::"), 56, 60)
fmt.Println(n.Count())                  // 4096
fmt.Println(n.Enumerate(2, 1024))       // [2001:db8:0:40:: 2001:db8:0:40:100::]
fmt.Println(n.FirstAddress())           // 2001:db8::
fmt.Println(n.NextIP(n.FirstAddress())) // 2001:db8:0:0:100:: <nil>
fmt.Println(n.LastAddress())            // 2001:db8:0:ff:f00::
fmt.Println(n.Mask().String())          // ffffffffffffff000000000000000000
fmt.Println(n.Hostmask.String())        // 0000000000000000f0ffffffffffffff
fmt.Println(n.Subnet(0, 60))            // [2001:db8::/57 2001:db8:0:80::/57] <nil>
fmt.Println(n.Supernet(0, 60))          // 2001:db8::/55 <nil>
```
