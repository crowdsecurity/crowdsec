package diff

/**
	Types are being split out to more closely follow the library structure already
    in place. Keeps the file simpler as well.
*/
import (
	"reflect"
	"strconv"
)

//renderSlice - handle slice rendering for patch
func (d *Differ) renderSlice(c *ChangeValue) {

	var err error
	field := c.change.Path[c.pos]

	//field better be an index of the slice
	if c.index, err = strconv.Atoi(field); err != nil {
		c.AddError(NewErrorf("invalid index in path. %s is not a number", field).
			WithCause(err))
	}
	var x reflect.Value
	if c.Len() > c.index {
		x = c.Index(c.index)
	}
	if !x.IsValid() {
		if !c.HasFlag(OptionOmitUnequal) {
			c.AddError(NewErrorf("Value index %d is invalid", c.index).
				WithCause(NewError("scanning for Value index")))
			for c.index = 0; c.index < c.Len(); c.index++ {
				y := c.Index(c.index)
				if reflect.DeepEqual(y, c.change.From) {
					c.AddError(NewErrorf("Value changed index to %d", c.index))
					x = y
					break
				}
			}
		}
	}
	if !x.IsValid() && c.change.Type != DELETE && !c.HasFlag(OptionNoCreate) {
		x = c.NewArrayElement()
	}
	if !x.IsValid() && c.change.Type == DELETE {
		c.index = -1 //no existing element to delete so don't bother
	}
	c.swap(&x) //containers must swap out the parent Value
}

//deleteSliceEntry - deletes are special, they are handled differently based on options
//              container type etc. We have to have special handling for each
//              type. Set values are more generic even if they must be instanced
func (d *Differ) deleteSliceEntry(c *ChangeValue) {
	//for a slice with only one element
	if c.ParentLen() == 1 && c.index != -1 {
		c.ParentSet(reflect.MakeSlice(c.parent.Type(), 0, 0), d.ConvertCompatibleTypes)
		c.SetFlag(FlagDeleted)
		//for a slice with multiple elements
	} else if c.index != -1 { //this is an array delete the element from the parent
		c.ParentIndex(c.index).Set(c.ParentIndex(c.ParentLen() - 1))
		c.ParentSet(c.parent.Slice(0, c.ParentLen()-1), d.ConvertCompatibleTypes)
		c.SetFlag(FlagDeleted)
		//for other slice elements, we ignore
	} else {
		c.SetFlag(FlagIgnored)
	}
}
