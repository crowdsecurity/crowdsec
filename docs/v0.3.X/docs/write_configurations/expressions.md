# Expressions

> [antonmedv/expr](https://github.com/antonmedv/expr) - Expression evaluation engine for Go: fast, non-Turing complete, dynamic typing, static typing

Several places of {{v0X.crowdsec.name}}'s configuration use [expr](https://github.com/antonmedv/expr), notably :

 - {{v0X.filter.Htmlname}} that are used to determine events eligibility in {{v0X.parsers.htmlname}} and {{v0X.scenarios.htmlname}} or `profiles`
 - {{v0X.statics.Htmlname}} use expr in the `expression` directive, to compute complex values
 - {{v0X.whitelists.Htmlname}} rely on `expression` directive to allow more complex whitelists filters

To learn more about [expr](https://github.com/antonmedv/expr), [check the github page of the project](https://github.com/antonmedv/expr/blob/master/docs/Language-Definition.md).


When {{v0X.crowdsec.name}} relies on `expr`, a context is provided to let the expression access relevant objects :

 - `evt.` is the representation of the current {{v0X.event.htmlname}} and is the most relevant object
 - in [profiles](/Crowdsec/v0/references/output/#profile), {{v0X.signal.htmlname}} is accessible via the `sig.` object

If the `debug` is enabled (in the scenario or parser where expr is used), additional debug will be displayed regarding evaluated expressions.


# Helpers

In order to makes its use in {{v0X.crowdsec.name}} more efficient, we added a few helpers that are documented bellow.

## Atof(string) float64

Parses a string representation of a float number to an actual float number (binding on `strconv.ParseFloat`)

> Atof(evt.Parsed.tcp_port)


## JsonExtract(JsonBlob, FieldName) string

Extract the `FieldName` from the `JsonBlob` and returns it as a string. (binding on [jsonparser](https://github.com/buger/jsonparser/))

> JsonExtract(evt.Parsed.some_json_blob, "foo.bar[0].one_item")

## File(FileName) []string

Returns the content of `FileName` as an array of string, while providing cache mechanism.

> evt.Parsed.some_field in File('some_patterns.txt')
> any(File('rdns_seo_bots.txt'), { evt.Enriched.reverse_dns endsWith #})

## RegexpInFile(StringToMatch, FileName) bool

Returns `true` if the `StringToMatch` is matched by one of the expressions contained in `FileName` (uses RE2 regexp engine).

> RegexpInFile( evt.Enriched.reverse_dns, 'my_legit_seo_whitelists.txt')

## Upper(string) string

Returns the uppercase version of the string

> Upper("yop")

## IpInRange(IPStr, RangeStr) bool

Returns true if the IP `IPStr` is contained in the IP range `RangeStr` (uses `net.ParseCIDR`)

> IpInRange("1.2.3.4", "1.2.3.0/24")
