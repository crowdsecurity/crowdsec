# Expressions

> {{expr.htmlname}} : Expression evaluation engine for Go: fast, non-Turing complete, dynamic typing, static typing


Several places of {{crowdsec.name}}'s configuration use {{expr.htmlname}} :

 - {{filter.Htmlname}} that are used to determine events eligibility in {{parsers.htmlname}} and {{scenarios.htmlname}}
 - {{statics.Htmlname}} can as well use expr in the `expression` directive, to compute complex values
 - {{whitelists.Htmlname}} as well suppport the `expression` directive that can return a bool result to determine if the event is whitelisted
 - `profiles.yaml` filters


To learn more about {{expr.htmlname}}, [check the github page of the project](https://github.com/antonmedv/expr).

In order to makes it use in {{crowdsec.name}} more efficient, we added a few helpers that are documented bellow.


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


## Upper(string) string

Returns the uppercase version of the string

## IpInRange(IPStr, RangeStr) bool

Returns true if the IP `IPStr` is contained in the IP range `RangeStr` (uses `net.ParseCIDR`)