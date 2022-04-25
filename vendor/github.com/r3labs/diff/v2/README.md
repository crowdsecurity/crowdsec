# Diff [![PkgGoDev](https://pkg.go.dev/badge/github.com/r3labs/diff)](https://pkg.go.dev/github.com/r3labs/diff) [![Go Report Card](https://goreportcard.com/badge/github.com/r3labs/diff)](https://goreportcard.com/report/github.com/r3labs/diff) [![Build Status](https://travis-ci.com/r3labs/diff.svg?branch=master)](https://travis-ci.com/r3labs/diff)

A library for diffing golang structures and values.

Utilizing field tags and reflection, it is able to compare two structures of the same type and create a changelog of all modified values. The produced changelog can easily be serialized to json.

NOTE: All active development now takes place on the v2 branch.

## Installation

For version 2:
```
go get github.com/r3labs/diff/v2
```

## Changelog Format

When diffing two structures using `Diff`, a changelog will be produced. Any detected changes will populate the changelog array with a Change type:

```go
type Change struct {
	Type string      // The type of change detected; can be one of create, update or delete
	Path []string    // The path of the detected change; will contain any field name or array index that was part of the traversal
	From interface{} // The original value that was present in the "from" structure
	To   interface{} // The new value that was detected as a change in the "to" structure
}
```

Given the example below, we are diffing two slices where the third element has been removed:

```go
from := []int{1, 2, 3, 4}
to := []int{1, 2, 4}

changelog, _ := diff.Diff(from, to)
```

The resultant changelog should contain one change:

```go
Change{
    Type: "delete",
    Path: ["2"],
    From: 3,
    To:   nil,
}
```

## Supported Types

A diffable value can be/contain any of the following types:


| Type         | Supported |
| ------------ | --------- |
| struct       | ✔         |
| slice        | ✔         |
| string       | ✔         |
| int          | ✔         |
| bool         | ✔         |
| map          | ✔         |
| pointer      | ✔         |
| custom types | ✔         |


Please see the docs for more supported types, options and features.

### Tags

In order for struct fields to be compared, they must be tagged with a given name. All tag values are prefixed with `diff`. i.e. `diff:"items"`.

| Tag           | Usage                                                                                                                                                                                                                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-`           | Excludes a value from being diffed                                                                                                                                                                                                                                                              |
| `identifier`  | If you need to compare arrays by a matching identifier and not based on order, you can specify the `identifier` tag. If an identifiable element is found in both the from and to structures, they will be directly compared. i.e. `diff:"name, identifier"`                                     |
| `immutable`   | Will omit this struct field from diffing. When using `diff.StructValues()` these values will be added to the returned changelog. It's use case is for when we have nothing to compare a struct to and want to show all of its relevant values.                                                  |
| `nocreate`    | The default patch action is to allocate instances in the target strut, map or slice should they not exist. Adding this flag will tell patch to skip elements that it would otherwise need to allocate. This is separate from immutable, which is also honored while patching.                   |
| `omitunequal` | Patching is a 'best effort' operation, and will by default attempt to update the 'correct' member of the target even if the underlying value has already changed to something other than the value in the change log 'from'. This tag will selectively ignore values that are not a 100% match. |

## Usage

### Basic Example

Diffing a basic set of values can be accomplished using the diff functions. Any items that specify a "diff" tag using a name will be compared.

```go
import "github.com/r3labs/diff/v2"

type Order struct {
    ID    string `diff:"id"`
    Items []int  `diff:"items"`
}

func main() {
    a := Order{
        ID: "1234",
        Items: []int{1, 2, 3, 4},
    }

    b := Order{
        ID: "1234",
        Items: []int{1, 2, 4},
    }

    changelog, err := diff.Diff(a, b)
    ...
}
```

In this example, the output generated in the changelog will indicate that the third element with a value of '3' was removed from items.
When marshalling the changelog to json, the output will look like:

```json
[
    {
        "type": "delete",
        "path": ["items", "2"],
        "from": 3,
        "to": null
    }
]
```

### Options and Configuration

Options can be set on the differ at call time which effect how diff acts when building the change log.
```go
import "github.com/r3labs/diff/v2"

type Order struct {
    ID    string `diff:"id"`
    Items []int  `diff:"items"`
}

func main() {
    a := Order{
        ID: "1234",
        Items: []int{1, 2, 3, 4},
    }

    b := Order{
        ID: "1234",
        Items: []int{1, 2, 4},
    }

    changelog, err := diff.Diff(a, b, diff.DisableStructValues(), diff.AllowTypeMismatch(true))
    ...
}
```

You can also create a new instance of a differ that allows options to be set.

```go
import "github.com/r3labs/diff/v2"

type Order struct {
    ID    string `diff:"id"`
    Items []int  `diff:"items"`
}

func main() {
    a := Order{
        ID: "1234",
        Items: []int{1, 2, 3, 4},
    }

    b := Order{
        ID: "1234",
        Items: []int{1, 2, 4},
    }

    d, err := diff.NewDiffer(diff.SliceOrdering(true))
    if err != nil {
        panic(err)
    }

    changelog, err := d.Diff(a, b)
    ...
}
```

Supported options are:

`SliceOrdering` ensures that the ordering of items in a slice is taken into account

`DiscardComplexOrigin` is a directive to diff to omit additional origin information about structs. This alters the behavior of patch and can lead to some pitfalls and non-intuitive behavior if used. On the other hand, it can significantly reduce the memory footprint of large complex diffs.

`AllowTypeMismatch` is a global directive to either allow (true) or not to allow (false) patch apply the changes if 'from' is not equal. This is effectively a global version of the omitunequal tag.

`Filter` provides a callback that allows you to determine which fields the differ descends into

`DisableStructValues` disables populating a separate change for each item in a struct, where the struct is being compared to a nil Value.

`TagName` sets the tag name to use when getting field names and options.

### Patch and merge support
Diff additionally supports merge and patch. Similar in concept to text patching / merging the Patch function, given 
a change log and a target instance will make a _best effort_ to apply the changes in the change log to the variable
pointed to. The intention is that the target pointer is of the same type however, that doesn't necessarily have to be 
true. For example, two slices of differing structs may be similar enough to apply changes to in a polymorphic way, and 
patch will certainly try.

The patch function doesn't actually fail, and even if there are errors, it may succeed sufficiently for the task at hand.
To accommodate this patch keeps track of each change log option it attempts to apply and reports the details of what 
happened for further scrutiny.

```go
import "github.com/r3labs/diff/v2"

type Order struct {
    ID    string `diff:"id"`
    Items []int  `diff:"items"`
}

func main() {
    a := Order{
        ID: "1234",
        Items: []int{1, 2, 3, 4},
    }

    b := Order{
        ID: "1234",
        Items: []int{1, 2, 4},
    }

    c := Order{}
    changelog, err := diff.Diff(a, b)

    patchlog := diff.Patch(changelog, &c)
    //Note the lack of an error. Patch is best effort and uses flags to indicate actions taken
    //and keeps any errors encountered along the way for review
    fmt.Printf("Encountered %d errors while patching", patchlog.ErrorCount())
    ...
}
```

Instances of differ with options set can also be used when patching.

```go
package main

import "github.com/r3labs/diff/v2"

type Order struct {
	ID    string `json:"id"`
	Items []int  `json:"items"`
}

func main() {
    a := Order{
        ID:    "1234",
        Items: []int{1, 2, 3, 4},
        }

    b := Order{
        ID:    "1234",
        Items: []int{1, 2, 4},
    }

    d, _ := diff.NewDiffer(diff.TagName("json"))

    changelog, _ := d.Diff(a, b)

    d.Patch(changelog, &a)
    // reflect.DeepEqual(a, b) == true
}

```

As a convenience, there is a Merge function that allows one to take three interfaces and perform all the tasks at the same
time.

```go
import "github.com/r3labs/diff/v2"

type Order struct {
    ID    string `diff:"id"`
    Items []int  `diff:"items"`
}

func main() {
    a := Order{
        ID: "1234",
        Items: []int{1, 2, 3, 4},
    }

    b := Order{
        ID: "1234",
        Items: []int{1, 2, 4},
    }

    c := Order{}
    patchlog, err := diff.Merge(a, b, &c)
    if err != nil {
        fmt.Printf("Error encountered while diffing a & b")
    }
    fmt.Printf("Encountered %d errors while patching", patchlog.ErrorCount())
    ...
}
```
## Running Tests

```
make test
```

## Contributing

Please read through our
[contributing guidelines](CONTRIBUTING.md).
Included are directions for opening issues, coding standards, and notes on
development.

Moreover, if your pull request contains patches or features, you must include
relevant unit tests.

## Versioning

For transparency into our release cycle and in striving to maintain backward
compatibility, this project is maintained under [the Semantic Versioning guidelines](http://semver.org/).

## Copyright and License

Code and documentation copyright since 2015 r3labs.io authors.

Code released under
[the Mozilla Public License Version 2.0](LICENSE).
