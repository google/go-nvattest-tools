package libxml2xsd

import (
	"errors"
	"strings"
	"testing"
)

const testSchema = `<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:complexType>
      <xs:attribute name="id" type="xs:string" use="required"/>
    </xs:complexType>
  </xs:element>
</xs:schema>`

// TestErrorStrings pins the error strings that server/rim (and so the
// regression goldens) depend on. They must stay identical to
// github.com/lestrrat-go/libxml2. The libxml2 message after "parser error : "
// comes from the C library, so only the prefix is pinned.
func TestErrorStrings(t *testing.T) {
	t.Run("schema_not_xml", func(t *testing.T) {
		_, err := ParseSchema([]byte("this is not a valid schema"))
		const want = "failed to parse input: failed to read schema from memory: Entity: line 1: parser error : "
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Fatalf("ParseSchema() = %v, want prefix %q", err, want)
		}
	})
	t.Run("schema_not_xsd", func(t *testing.T) {
		_, err := ParseSchema([]byte("<root/>"))
		const want = "failed to parse input: failed to parse schema"
		if err == nil || err.Error() != want {
			t.Fatalf("ParseSchema() = %v, want %q", err, want)
		}
	})
	t.Run("document_not_xml", func(t *testing.T) {
		_, err := ParseString("< />")
		const want = "failed to create parse input: failed to read document from memory: Entity: line 1: parser error : "
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Fatalf("ParseString() = %v, want prefix %q", err, want)
		}
	})
	t.Run("document_empty", func(t *testing.T) {
		// Older libxml2 (2.9.13) refuses to create a parser for an empty buffer;
		// 2.15.4 creates it and fails in the read. Same as upstream.
		_, err := ParseString("")
		const want1 = "failed to create parse context: failed to execute XMLCreateMemoryParserCtxt: error creating parser"
		const want2 = "failed to create parse input: failed to read document from memory: "
		if err == nil || (err.Error() != want1 && !strings.HasPrefix(err.Error(), want2)) {
			t.Fatalf("ParseString() = %v, want %q or prefix %q", err, want1, want2)
		}
	})
	t.Run("schema_empty_panics", func(t *testing.T) {
		// Upstream panics here too. Pinned so a change is deliberate.
		defer func() {
			if recover() == nil {
				t.Fatal("ParseSchema(nil) did not panic")
			}
		}()
		_, _ = ParseSchema(nil)
	})
}

func TestValidate(t *testing.T) {
	s, err := ParseSchema([]byte(testSchema))
	if err != nil {
		t.Fatalf("ParseSchema() = %v", err)
	}
	defer s.Free()

	for _, tc := range []struct {
		name    string
		doc     string
		wantErr bool
	}{
		{name: "valid", doc: `<root id="x"/>`},
		{name: "missing_attribute", doc: `<root/>`, wantErr: true},
		{name: "wrong_root", doc: `<other id="x"/>`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseString(tc.doc)
			if err != nil {
				t.Fatalf("ParseString() = %v", err)
			}
			defer d.Free()
			err = s.Validate(d)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			var sve SchemaValidationError
			if !errors.As(err, &sve) || err.Error() != "schema validation failed" {
				t.Fatalf("Validate() = %v, want SchemaValidationError", err)
			}
			if len(sve.Errors()) == 0 {
				t.Error("Validate() returned no libxml2 messages")
			}
		})
	}
}

// TestManyErrors makes libxml2 report more than the accumulator holds and a
// message longer than its buffer: the over-long-message cases.
func TestManyErrors(t *testing.T) {
	s, err := ParseSchema([]byte(testSchema))
	if err != nil {
		t.Fatalf("ParseSchema() = %v", err)
	}
	defer s.Free()
	long := strings.Repeat("a", 4096)
	doc := `<root id="x" ` + long + `="1">` + strings.Repeat(`<x/>`, 100) + `</root>`
	d, err := ParseString(doc)
	if err != nil {
		t.Fatalf("ParseString() = %v", err)
	}
	defer d.Free()
	var sve SchemaValidationError
	if err := s.Validate(d); !errors.As(err, &sve) {
		t.Fatalf("Validate() = %v, want SchemaValidationError", err)
	}
	if n := len(sve.Errors()); n == 0 || n > 32 {
		t.Errorf("len(Errors()) = %d, want 1..32", n)
	}
	for _, e := range sve.Errors() {
		if len(e.Error()) > 1023 {
			t.Errorf("message length %d, want <= 1023", len(e.Error()))
		}
	}
}

// TestRepeat runs parse, validate and free many times. Run it under
// `go test -asan` to check for leaks, double frees and use after free.
func TestRepeat(t *testing.T) {
	for i := 0; i < 200; i++ {
		s, err := ParseSchema([]byte(testSchema))
		if err != nil {
			t.Fatalf("ParseSchema() = %v", err)
		}
		d, err := ParseString(`<root/>`)
		if err != nil {
			t.Fatalf("ParseString() = %v", err)
		}
		if err := s.Validate(d); err == nil {
			t.Fatal("Validate() = nil, want error")
		}
		d.Free()
		s.Free()
		if _, err := ParseSchema([]byte("<root/>")); err == nil {
			t.Fatal("ParseSchema(<root/>) = nil error")
		}
	}
}
