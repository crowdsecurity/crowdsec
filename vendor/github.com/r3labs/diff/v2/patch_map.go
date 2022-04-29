package diff

import (
	"errors"
	"reflect"

	"github.com/vmihailenco/msgpack"
)

//renderMap - handle map rendering for patch
func (d *Differ) renderMap(c *ChangeValue) (m, k, v *reflect.Value) {
	//we must tease out the type of the key, we use the msgpack from diff to recreate the key
	kt := c.target.Type().Key()
	field := reflect.New(kt)

	if d.StructMapKeys {
		if err := msgpack.Unmarshal([]byte(c.change.Path[c.pos]), field.Interface()); err != nil {
			c.SetFlag(FlagIgnored)
			c.AddError(NewError("Unable to unmarshal path element to target type for key in map", err))
			return
		}
		c.key = field.Elem()
	} else {
		c.key = reflect.ValueOf(c.change.Path[c.pos])
	}

	if c.target.IsNil() && c.target.IsValid() {
		c.target.Set(reflect.MakeMap(c.target.Type()))
	}

	// we need to check that MapIndex does not panic here
	// when the key type is not a string
	defer func() {
		if err := recover(); err != nil {
			switch x := err.(type) {
			case error:
				c.AddError(NewError("Unable to unmarshal path element to target type for key in map", x))
			case string:
				c.AddError(NewError("Unable to unmarshal path element to target type for key in map", errors.New(x)))
			}
			c.SetFlag(FlagIgnored)
		}
	}()

	x := c.target.MapIndex(c.key)

	if !x.IsValid() && c.change.Type != DELETE && !c.HasFlag(OptionNoCreate) {
		x = c.NewElement()
	}
	if x.IsValid() { //Map elements come out as read only so we must convert
		nv := reflect.New(x.Type()).Elem()
		nv.Set(x)
		x = nv
	}

	if x.IsValid() && !reflect.DeepEqual(c.change.From, x.Interface()) &&
		c.HasFlag(OptionOmitUnequal) {
		c.SetFlag(FlagIgnored)
		c.AddError(NewError("target change doesn't match original"))
		return
	}
	mp := *c.target //these may change out from underneath us as we recurse
	key := c.key    //so we make copies and pass back pointers to them
	c.swap(&x)

	return &mp, &key, &x

}

// updateMapEntry - deletes are special, they are handled differently based on options
//            container type etc. We have to have special handling for each
//            type. Set values are more generic even if they must be instanced
func (d *Differ) updateMapEntry(c *ChangeValue, m, k, v *reflect.Value) {
	if k == nil || m == nil {
		return
	}

	switch c.change.Type {
	case DELETE:
		if c.HasFlag(FlagDeleted) {
			return
		}

		if !m.CanSet() && v.IsValid() && v.Kind() == reflect.Struct {
			for x := 0; x < v.NumField(); x++ {
				if !v.Field(x).IsZero() {
					m.SetMapIndex(*k, *v)
					return
				}
			} //if all the fields are zero, remove from map
		}

		m.SetMapIndex(*k, reflect.Value{})
		c.SetFlag(FlagDeleted)

	case CREATE:
		m.SetMapIndex(*k, *v)
		c.SetFlag(FlagCreated)

	case UPDATE:
		m.SetMapIndex(*k, *v)
		c.SetFlag(FlagUpdated)

	}
}
