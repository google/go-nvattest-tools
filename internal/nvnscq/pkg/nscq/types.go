package nscq

// Return is the return code for NSCQ operations.
type Return int32

// UUID is a universally unique identifier.
type UUID struct {
	data [uuidDataLength]byte
}

// Label is a label for an NSCQ object.
type Label struct {
	data [labelDataLength]byte
}

// Session is a session for an NSCQ operation.
type Session struct{}
