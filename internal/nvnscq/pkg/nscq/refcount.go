package nscq

// refcount is a simple integer that tracks the number of references to a resource.
type refcount int

func (r *refcount) IncOnNoError(err error) {
	if err == nil {
		(*r)++
	}
}

func (r *refcount) DecOnNoError(err error) {
	if err == nil && (*r) > 0 {
		(*r)--
	}
}
