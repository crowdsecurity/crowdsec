package schema

import (
	"time"
)

func UtcNow() time.Time {
	return time.Now().UTC()
}
