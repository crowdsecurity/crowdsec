package diff

import (
	"reflect"
)

/**
	This is a method of applying a changelog to a value or struct. change logs
    should be generated with Diff and never manually created. This DOES NOT
    apply fuzzy logic as would be in the case of a text patch. It does however
    have a few additional features added to our struct tags.

	1) create. This tag on a struct field indicates that the patch should
       create the value if it's not there. I.e. if it's nil. This works for
       pointers, maps and slices.

	2) omitunequal. Generally, you don't want to do this, the expectation is
       that if an item isn't there, you want to add it. For example, if your
       diff shows an array element at index 6 is a string 'hello' but your target
       only has 3 elements, none of them matching... you want to add 'hello'
       regardless of the index. (think in a distributed context, another process
       may have deleted more than one entry and 'hello' may no longer be in that
       indexed spot.

       So given this scenario, the default behavior is to scan for the previous
       value and replace it anyway, or simply append the new value. For maps the
       default behavior is to simply add the key if it doesn't match.

       However, if you don't like the default behavior, and add the omitunequal
       tag to your struct, patch will *NOT* update an array or map with the key
       or array value unless they key or index contains a 'match' to the
       previous value. In which case it will skip over that change.

    Patch is implemented as a best effort algorithm. That means you can receive
    multiple nested errors and still successfully have a modified target. This
    may even be acceptable depending on your use case. So keep in mind, just
    because err != nil *DOESN'T* mean that the patch didn't accomplish your goal
    in setting those changes that are actually available. For example, you may
    diff two structs of the same type, then attempt to apply to an entirely
    different struct that is similar in constitution (think interface here) and
    you may in fact get all of the values populated you wished to anyway.
*/

//Not strictly necessary but might be nice in some cases
//go:generate stringer -type=PatchFlags
type PatchFlags uint32

const (
	OptionCreate PatchFlags = 1 << iota
	OptionNoCreate
	OptionOmitUnequal
	OptionImmutable
	FlagInvalidTarget
	FlagApplied
	FlagFailed
	FlagCreated
	FlagIgnored
	FlagDeleted
	FlagUpdated
	FlagParentSetApplied
	FlagParentSetFailed
)

//PatchLogEntry defines how a DiffLog entry was applied
type PatchLogEntry struct {
	Path   []string    `json:"path"`
	From   interface{} `json:"from"`
	To     interface{} `json:"to"`
	Flags  PatchFlags  `json:"flags"`
	Errors error       `json:"errors"`
}
type PatchLog []PatchLogEntry

//HasFlag - convenience function for users
func (p PatchLogEntry) HasFlag(flag PatchFlags) bool {
	return (p.Flags & flag) != 0
}

//Applied - returns true if all change log entries were actually
//          applied, regardless of if any errors were encountered
func (p PatchLog) Applied() bool {
	if p.HasErrors() {
		for _, ple := range p {
			if !ple.HasFlag(FlagApplied) {
				return false
			}
		}
	}
	return true
}

//HasErrors - indicates if a patch log contains any errors
func (p PatchLog) HasErrors() (ret bool) {
	for _, ple := range p {
		if ple.Errors != nil {
			ret = true
		}
	}
	return
}

//ErrorCount -- counts the number of errors encountered while patching
func (p PatchLog) ErrorCount() (ret uint) {
	for _, ple := range p {
		if ple.Errors != nil {
			ret++
		}
	}
	return
}

func Merge(original interface{}, changed interface{}, target interface{}) (PatchLog, error) {
	d, _ := NewDiffer()
	return d.Merge(original, changed, target)
}

// Merge is a convenience function that diffs, the original and changed items
// and merges said changes with target all in one call.
func (d *Differ) Merge(original interface{}, changed interface{}, target interface{}) (PatchLog, error) {
	StructMapKeySupport()(d) // nolint: errcheck
	if cl, err := d.Diff(original, changed); err == nil {
		return Patch(cl, target), nil
	} else {
		return nil, err
	}
}

func Patch(cl Changelog, target interface{}) (ret PatchLog) {
	d, _ := NewDiffer()
	return d.Patch(cl, target)
}

//Patch... the missing feature.
func (d *Differ) Patch(cl Changelog, target interface{}) (ret PatchLog) {
	for _, c := range cl {
		ret = append(ret, NewPatchLogEntry(NewChangeValue(d, c, target)))
	}
	return ret
}

//NewPatchLogEntry converts our complicated reflection based struct to
//a simpler format for the consumer
func NewPatchLogEntry(cv *ChangeValue) PatchLogEntry {
	return PatchLogEntry{
		Path:   cv.change.Path,
		From:   cv.change.From,
		To:     cv.change.To,
		Flags:  cv.flags,
		Errors: cv.err,
	}
}

//NewChangeValue idiomatic constructor (also invokes render)
func NewChangeValue(d *Differ, c Change, target interface{}) (ret *ChangeValue) {
	val := reflect.ValueOf(target)
	ret = &ChangeValue{
		target: &val,
		change: &c,
	}
	d.renderChangeTarget(ret)
	return
}

//renderChangeValue applies 'path' in change to target. nil check is foregone
//                  here as we control usage
func (d *Differ) renderChangeTarget(c *ChangeValue) {
	//This particular change element may potentially have the immutable flag
	if c.HasFlag(OptionImmutable) {
		c.AddError(NewError("Option immutable set, cannot apply change"))
		return
	} //the we always set a failure, and only unset if we successfully render the element
	c.SetFlag(FlagInvalidTarget)

	//substitute and solve for t (path)
	switch c.target.Kind() {

	//path element that is a map
	case reflect.Map:
		//map elements are 'copies' and immutable so if we set the new value to the
		//map prior to editing the value, it will fail to stick. To fix this, we
		//defer the safe until the stack unwinds
		m, k, v := d.renderMap(c)
		defer d.updateMapEntry(c, m, k, v)

	//path element that is a slice
	case reflect.Slice:
		d.renderSlice(c)

	//walking a path means dealing with real elements
	case reflect.Interface, reflect.Ptr:
		el := c.target.Elem()
		c.target = &el
		c.ClearFlag(FlagInvalidTarget)

	//path element that is a struct
	case reflect.Struct:
		d.patchStruct(c)
	}

	//if for some reason, rendering this element fails, c will no longer be valid
	//we are best effort though, so we keep on trucking
	if !c.IsValid() {
		c.AddError(NewErrorf("Unable to access path position %d. Target field is invalid", c.pos))
	}

	//we've taken care of this path element, are there any more? if so, process
	//else, let's take some action
	if c.pos < len(c.change.Path) && !c.HasFlag(FlagInvalidTarget) {
		d.renderChangeTarget(c)

	} else { //we're at the end of the line... set the Value
		switch c.change.Type {
		case DELETE:
			switch c.ParentKind() {
			case reflect.Slice:
				d.deleteSliceEntry(c)
			case reflect.Struct:
				d.deleteStructEntry(c)
			default:
				c.SetFlag(FlagIgnored)
			}
		case UPDATE, CREATE:
			// this is generic because... we only deal in primitives here. AND
			// the diff format To field already contains the correct type.
			c.Set(reflect.ValueOf(c.change.To), d.ConvertCompatibleTypes)
			c.SetFlag(FlagUpdated)
		}
	}
}
