package diff

// ConvertTypes enables values that are convertible to the target type to be converted when patching
func ConvertCompatibleTypes() func(d *Differ) error {
	return func(d *Differ) error {
		d.ConvertCompatibleTypes = true
		return nil
	}
}

// FlattenEmbeddedStructs determines whether fields of embedded structs should behave as if they are directly under the parent
func FlattenEmbeddedStructs() func(d *Differ) error {
	return func(d *Differ) error {
		d.FlattenEmbeddedStructs = true
		return nil
	}
}

// SliceOrdering determines whether the ordering of items in a slice results in a change
func SliceOrdering(enabled bool) func(d *Differ) error {
	return func(d *Differ) error {
		d.SliceOrdering = enabled
		return nil
	}
}

// TagName sets the tag name to use when getting field names and options
func TagName(tag string) func(d *Differ) error {
	return func(d *Differ) error {
		d.TagName = tag
		return nil
	}
}

// DisableStructValues disables populating a separate change for each item in a struct,
// where the struct is being compared to a nil value
func DisableStructValues() func(d *Differ) error {
	return func(d *Differ) error {
		d.DisableStructValues = true
		return nil
	}
}

// CustomValueDiffers allows you to register custom differs for specific types
func CustomValueDiffers(vd ...ValueDiffer) func(d *Differ) error {
	return func(d *Differ) error {
		d.customValueDiffers = append(d.customValueDiffers, vd...)
		for k := range d.customValueDiffers {
			d.customValueDiffers[k].InsertParentDiffer(d.diff)
		}
		return nil
	}
}

// AllowTypeMismatch changed behaviour to report value as "updated" when its type has changed instead of error
func AllowTypeMismatch(enabled bool) func(d *Differ) error {
	return func(d *Differ) error {
		d.AllowTypeMismatch = enabled
		return nil
	}
}

//StructMapKeySupport - Changelog paths do not provided structured object values for maps that contain complex
//keys (such as other structs). You must enable this support via an option and it then uses msgpack to encode
//path elements that are structs. If you don't have this on, and try to patch, your apply will fail for that
//element.
func StructMapKeySupport() func(d *Differ) error {
	return func(d *Differ) error {
		d.StructMapKeys = true
		return nil
	}
}

//DiscardComplexOrigin - by default, we are now keeping the complex struct associated with a create entry.
//This allows us to fix the merge to new object issue of not having enough change log details when allocating
//new objects. This however is a trade off of memory size and complexity vs correctness which is often only
//necessary when embedding structs in slices and arrays. It memory constrained environments, it may be desirable
//to turn this feature off however from a computational perspective, keeping the complex origin is actually quite
//cheap so, make sure you're extremely clear on the pitfalls of turning this off prior to doing so.
func DiscardComplexOrigin() func(d *Differ) error {
	return func(d *Differ) error {
		d.DiscardParent = true
		return nil
	}
}

// Filter allows you to determine which fields the differ descends into
func Filter(f FilterFunc) func(d *Differ) error {
	return func(d *Differ) error {
		d.Filter = f
		return nil
	}
}
