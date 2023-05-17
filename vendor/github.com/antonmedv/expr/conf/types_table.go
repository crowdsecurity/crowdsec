package conf

import (
	"reflect"
)

type Tag struct {
	Type        reflect.Type
	Ambiguous   bool
	FieldIndex  []int
	Method      bool
	MethodIndex int
}

type TypesTable map[string]Tag

// CreateTypesTable creates types table for type checks during parsing.
// If struct is passed, all fields will be treated as variables,
// as well as all fields of embedded structs and struct itself.
//
// If map is passed, all items will be treated as variables
// (key as name, value as type).
func CreateTypesTable(i interface{}) TypesTable {
	if i == nil {
		return nil
	}

	types := make(TypesTable)
	v := reflect.ValueOf(i)
	t := reflect.TypeOf(i)

	d := t
	if t.Kind() == reflect.Ptr {
		d = t.Elem()
	}

	switch d.Kind() {
	case reflect.Struct:
		types = FieldsFromStruct(d)

		// Methods of struct should be gathered from original struct with pointer,
		// as methods maybe declared on pointer receiver. Also this method retrieves
		// all embedded structs methods as well, no need to recursion.
		for i := 0; i < t.NumMethod(); i++ {
			m := t.Method(i)
			types[m.Name] = Tag{
				Type:        m.Type,
				Method:      true,
				MethodIndex: i,
			}
		}

	case reflect.Map:
		for _, key := range v.MapKeys() {
			value := v.MapIndex(key)
			if key.Kind() == reflect.String && value.IsValid() && value.CanInterface() {
				types[key.String()] = Tag{Type: reflect.TypeOf(value.Interface())}
			}
		}

		// A map may have method too.
		for i := 0; i < t.NumMethod(); i++ {
			m := t.Method(i)
			types[m.Name] = Tag{
				Type:        m.Type,
				Method:      true,
				MethodIndex: i,
			}
		}
	}

	return types
}

func FieldsFromStruct(t reflect.Type) TypesTable {
	types := make(TypesTable)
	t = dereference(t)
	if t == nil {
		return types
	}

	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)

			if f.Anonymous {
				for name, typ := range FieldsFromStruct(f.Type) {
					if _, ok := types[name]; ok {
						types[name] = Tag{Ambiguous: true}
					} else {
						typ.FieldIndex = append(f.Index, typ.FieldIndex...)
						types[name] = typ
					}
				}
			}

			types[FieldName(f)] = Tag{
				Type:       f.Type,
				FieldIndex: f.Index,
			}
		}
	}

	return types
}

func dereference(t reflect.Type) reflect.Type {
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Ptr {
		t = dereference(t.Elem())
	}
	return t
}

func FieldName(field reflect.StructField) string {
	if taggedName := field.Tag.Get("expr"); taggedName != "" {
		return taggedName
	}
	return field.Name
}
