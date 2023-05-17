# Notable rationale of go-re2

## No Close method

This library does not add a `Close` method to `Regexp` to allow manually freeing native memory as is
typical with libraries that wrap C++ in Go. A finalizer is set to allow release when the GC reclaims
the object. In many other cases of native wrappers, this is not sufficient - the GC will not be aware
of the real memory usage on the native side and not perform correctly.

In this library, we have chosen not to add it because in the default mode for Go apps using wazero,
the above limitation is not true. Because wazero itself allocates the memory used by the WebAssembly
module, all the memory allocated in C++ code is actually allocated by the Go GC. This means the GC
does know exactly how much memory is used by `Regexp` and acts correctly.

However, for cgo or TinyGo, this is not the case. We still go ahead and leave out `Close` for now
for the less concrete reason that closing would generally only be needed with short-lived regular
expressions. Compilation time with this library takes much longer than the standard library - it is
not appropriate for use with short-lived expressions. In the case that it is acceptable and the
static match functions are used, the regular expressions will be freed as soon as they're used.
If code decides to use this library and has short-lived compiled expressions, rather than adding
`Close` it should be simple to switch to the match functions instead.

This leaves medium-lived expressions as a use case for `Close` - for example there may be some
business logic that is dynamically loaded and unloaded that gets compiled as regex. For now, we
will leave it as future work to add `Close` for this use case, under cgo or TinyGo, if it gets
asked for. All other use cases are expected to work fine without it.

## No implementation of Reader methods

The standard library gives leeway to read an arbitrary amount of input from a `Reader` when processing.
This means that we could implement the API surface by reading the entire string and passing to re2.
This defeats the purpose of the `Reader` methods though, and we choose to keep it a compilation failure.
For applications where buffering the entire string is acceptable, they can be rewritten to do so in their
logic, while when not acceptable it is fine to continue to use the standard library.
