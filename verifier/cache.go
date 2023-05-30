package verifier

import "time"

type Cache interface {
	Add(k string, x interface{}, d time.Duration) error
	Get(k string) (interface{}, bool)
	Delete(k string)
}
