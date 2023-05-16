package diff

import (
	"fmt"
	"reflect"
)

//ChangeValue is a specialized struct for monitoring patching
type ChangeValue struct {
	parent *reflect.Value
	target *reflect.Value
	flags  PatchFlags
	change *Change
	err    error
	pos    int
	index  int
	key    reflect.Value
}

//swap swaps out the target as we move down the path. Note that a nil
//     check is foregone here due to the fact we control usage.
func (c *ChangeValue) swap(newTarget *reflect.Value) {
	if newTarget.IsValid() {
		c.ClearFlag(FlagInvalidTarget)
		c.parent = c.target
		c.target = newTarget
		c.pos++
	}
}

// Sets a flag on the node and saves the change
func (c *ChangeValue) SetFlag(flag PatchFlags) {
	if c != nil {
		c.flags = c.flags | flag
	}
}

//ClearFlag removes just a single flag
func (c *ChangeValue) ClearFlag(flag PatchFlags) {
	if c != nil {
		c.flags = c.flags &^ flag
	}
}

//HasFlag indicates if a flag is set on the node. returns false if node is bad
func (c *ChangeValue) HasFlag(flag PatchFlags) bool {
	return (c.flags & flag) != 0
}

//IsValid echo for is valid
func (c *ChangeValue) IsValid() bool {
	if c != nil {
		return c.target.IsValid() || !c.HasFlag(FlagInvalidTarget)
	}
	return false
}

//ParentKind - helps keep us nil safe
func (c ChangeValue) ParentKind() reflect.Kind {
	if c.parent != nil {
		return c.parent.Kind()
	}
	return reflect.Invalid
}

//ParentLen is a nil safe parent length check
func (c ChangeValue) ParentLen() (ret int) {
	if c.parent != nil &&
		(c.parent.Kind() == reflect.Slice ||
			c.parent.Kind() == reflect.Map) {
		ret = c.parent.Len()
	}
	return
}

//ParentSet - nil safe parent set
func (c *ChangeValue) ParentSet(value reflect.Value, convertCompatibleTypes bool) {
	if c != nil && c.parent != nil {
		defer func() {
			if r := recover(); r != nil {
				c.SetFlag(FlagParentSetFailed)
			}
		}()

		if convertCompatibleTypes {
			if !value.Type().ConvertibleTo(c.parent.Type()) {
				c.AddError(fmt.Errorf("Value of type %s is not convertible to %s", value.Type().String(), c.parent.Type().String()))
				c.SetFlag(FlagParentSetFailed)
				return
			}
			c.parent.Set(value.Convert(c.parent.Type()))
		} else {
			c.parent.Set(value)
		}
		c.SetFlag(FlagParentSetApplied)
	}
}

//Len echo for len
func (c ChangeValue) Len() int {
	return c.target.Len()
}

//Set echos reflect set
func (c *ChangeValue) Set(value reflect.Value, convertCompatibleTypes bool) {
	if c != nil {
		defer func() {
			if r := recover(); r != nil {
				c.AddError(NewError(r.(string)))
				c.SetFlag(FlagFailed)
			}
		}()
		if c.HasFlag(OptionImmutable) {
			c.SetFlag(FlagIgnored)
			return
		}

		if convertCompatibleTypes {
			if !value.Type().ConvertibleTo(c.target.Type()) {
				c.AddError(fmt.Errorf("Value of type %s is not convertible to %s", value.Type().String(), c.target.Type().String()))
				c.SetFlag(FlagFailed)
				return
			}
			c.target.Set(value.Convert(c.target.Type()))
		} else {
			if value.IsValid() {
				c.target.Set(value)
			} else if !c.target.IsZero() {
				t := c.target.Elem()
				t.Set(reflect.Zero(t.Type()))
			}
		}
		c.SetFlag(FlagApplied)
	}
}

//Index echo for index
func (c ChangeValue) Index(i int) reflect.Value {
	return c.target.Index(i)
}

//ParentIndex - get us the parent version, nil safe
func (c ChangeValue) ParentIndex(i int) (ret reflect.Value) {
	if c.parent != nil {
		ret = c.parent.Index(i)
	}
	return
}

//Instance a new element of type for target. Taking the
//copy of the complex origin avoids the 'lack of data' issue
//present when allocating complex structs with slices and
//arrays
func (c ChangeValue) NewElement() reflect.Value {
	ret := c.change.parent
	if ret != nil {
		return reflect.ValueOf(ret)
	}
	return reflect.New(c.target.Type().Elem()).Elem()
}

//NewArrayElement gives us a dynamically typed new element
func (c ChangeValue) NewArrayElement() reflect.Value {
	c.target.Set(reflect.Append(*c.target, c.NewElement()))
	c.SetFlag(FlagCreated)
	return c.Index(c.Len() - 1)
}

//AddError appends errors to this change value
func (c *ChangeValue) AddError(err error) *ChangeValue {
	if c != nil {
		c.err = err
	}
	return c
}
