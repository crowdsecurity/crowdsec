package diff

import "reflect"

/**
	Types are being split out to more closely follow the library structure already
    in place. Keeps the file simpler as well.
*/

type structField struct {
	f reflect.StructField
	v reflect.Value
}

func getNestedFields(v reflect.Value, flattenEmbedded bool) []structField {
	fields := make([]structField, 0)

	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		fv := v.Field(i)

		if fv.Kind() == reflect.Struct && f.Anonymous && flattenEmbedded {
			fields = append(fields, getNestedFields(fv, flattenEmbedded)...)
		} else {
			fields = append(fields, structField{f, fv})
		}
	}

	return fields
}

//patchStruct - handles the rendering of a struct field
func (d *Differ) patchStruct(c *ChangeValue) {

	field := c.change.Path[c.pos]

	structFields := getNestedFields(*c.target, d.FlattenEmbeddedStructs)
	for _, structField := range structFields {
		f := structField.f
		tname := tagName(d.TagName, f)
		if tname == "-" {
			continue
		}
		if tname == field || f.Name == field {
			x := structField.v
			if hasTagOption(d.TagName, f, "nocreate") {
				c.SetFlag(OptionNoCreate)
			}
			if hasTagOption(d.TagName, f, "omitunequal") {
				c.SetFlag(OptionOmitUnequal)
			}
			if hasTagOption(d.TagName, f, "immutable") {
				c.SetFlag(OptionImmutable)
			}
			c.swap(&x)
			break
		}
	}
}

//track and zero out struct members
func (d *Differ) deleteStructEntry(c *ChangeValue) {

	//deleting a struct value set's it to the 'basic' type
	c.Set(reflect.Zero(c.target.Type()), d.ConvertCompatibleTypes)
}
