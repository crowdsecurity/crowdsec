// Package schemaspec provides types designed to capture atlas schema elements, and create
// type-safe extensions to the configuration language. This package is designed to provide
// an intermediate representation between a serialized configuration language representation
// (Atlas HCL, JSON, YAML, etc.) and concrete representations that are created and handled
// by a specific driver.
//
// The basic type that is handled in this package is schemaspec.Resource which is a generic
// container for resources described in Atlas configurations. A resource has a set of "Attr" instances
// associated with it, as well a a list of children schemaspec.Resource instances that can be associated
// with it.
//
// Users of Atlas applications are expected to interface with this package via a configuration
// language package. For example, via the `schemahcl` package:
//
//   schemahcl.Unmarshal([]byte(`
//		table "users" {
//			column "id" {
//				type = "int"
//			}
//		}
//  `), &someStruct{})
//
// Applications working with the Atlas DDL  are expected to extend the Atlas language by
// defining their own type structs  that objects can be handled in a type-safe way. Resource
// objects provide the `As` method to read a resource into an extension struct, as well as a
// `Scan` method to read an extension struct back into a Resource.
//
// The mapping between the extension struct fields and a Resource is done by placing tags on the
// extension struct field using the `spec` key in the tag. To specify that a field should be mapped to
// the corresponding Resource's `Name` specify ",name" to the tag value. For example,
//
//  type Point struct {
//      ID string `spec:",name"`
//      X  int    `spec:"x"
//      Y  int    `spec:"y"
//  }
//
// Would be able to capture a Resource defined in Atlas HCL as:
//
//	point "origin" {
//		x = 100
//		y = 200
//	}
//
// Extension structs may implement the Remainer interface if they wish to store
// any attributes and children that are not matched by their tagged fields. As a convenience
// the package exports a DefaultExtension type that can be embedded to support this behavior.
package schemaspec
