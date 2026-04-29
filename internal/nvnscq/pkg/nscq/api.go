package nscq

// ExtendedInterface defines a set of extensions to the core NSCQ API.
type ExtendedInterface interface {
	LookupSymbol(string) error
}

// libraryOptions hold the paramaters than can be set by a LibraryOption
type libraryOptions struct {
	path  string
	flags int
}

// LibraryOption represents a functional option to configure the underlying NSCQ library
type LibraryOption func(*libraryOptions)

// WithLibraryPath provides an option to set the library name to be used by the NSCQ library.
func WithLibraryPath(path string) LibraryOption {
	return func(o *libraryOptions) {
		o.path = path
	}
}
