package cwhub

import (
	"errors"
)

/*To be used when reference(s) (is/are) missing in a collection*/
var ReferenceMissingError = errors.New("Reference(s) missing in collection")
