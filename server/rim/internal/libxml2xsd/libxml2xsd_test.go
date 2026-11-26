package libxml2xsd

import (
	"errors"
	"fmt"
	"strings"
	"sync"
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

// TestErrorStrings pins the error strings wrapped by (*Data).ValidateSchema
// in server/rim/rim.go. They must stay identical to
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
		t.Fatalf("ParseSchema(testSchema) = %v, want nil", err)
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
				t.Fatalf("ParseString(%q) = %v, want nil", tc.doc, err)
			}
			defer d.Free()
			err = s.Validate(d)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Validate(%q) = %v, want nil", tc.doc, err)
				}
				return
			}
			var sve SchemaValidationError
			if !errors.As(err, &sve) || err.Error() != "schema validation failed" {
				t.Fatalf("Validate(%q) = %v, want SchemaValidationError(%q)", tc.doc, err, "schema validation failed")
			}
			if len(sve.Errors()) == 0 {
				t.Errorf("Validate(%q) returned 0 libxml2 messages, want >= 1", tc.doc)
			}
		})
	}
}

// TestManyErrors makes libxml2 report more errors than the 32-entry
// accumulator holds and at least one message longer than its 1024-byte buffer.
func TestManyErrors(t *testing.T) {
	s, err := ParseSchema([]byte(testSchema))
	if err != nil {
		t.Fatalf("ParseSchema(testSchema) = %v, want nil", err)
	}
	defer s.Free()

	var doc strings.Builder
	doc.WriteString(`<root id="x" `)
	doc.WriteString(strings.Repeat("a", 4096))
	doc.WriteString(`="1"`)
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&doc, ` bad%d="1"`, i)
	}
	doc.WriteString(`/>`)

	d, err := ParseString(doc.String())
	if err != nil {
		t.Fatalf("ParseString(many-attribute doc) = %v, want nil", err)
	}
	defer d.Free()

	var sve SchemaValidationError
	if err := s.Validate(d); !errors.As(err, &sve) {
		t.Fatalf("Validate(many-attribute doc) = %v, want SchemaValidationError", err)
	}
	if n := len(sve.Errors()); n != 32 {
		t.Errorf("len(Errors()) = %d, want 32", n)
	}
	sawTruncated := false
	for i, e := range sve.Errors() {
		if l := len(e.Error()); l > 1023 {
			t.Errorf("Errors()[%d] length = %d, want <= 1023", i, l)
		} else if l == 1023 {
			sawTruncated = true
		}
	}
	if !sawTruncated {
		t.Error("expected at least one error message truncated to 1023 bytes, got none")
	}
}

// TestFreeAndUseAfterFree verifies nil receivers, double Free, and Validate
// calls after Schema.Free or Document.Free return errors instead of crashing.
func TestFreeAndUseAfterFree(t *testing.T) {
	t.Run("nil_receivers", func(t *testing.T) {
		var s *Schema
		var d *Document
		s.Free()
		d.Free()

		var sve SchemaValidationError
		err := s.Validate(d)
		if !errors.As(err, &sve) {
			t.Fatalf("(*Schema)(nil).Validate(nil) = %v, want SchemaValidationError", err)
		}
		if got := sve.Errors(); len(got) != 1 || got[0].Error() != "invalid schema" {
			t.Errorf("(*Schema)(nil).Validate(nil) details = %v, want [invalid schema]", got)
		}
	})

	t.Run("double_free_and_validate_after_schema_free", func(t *testing.T) {
		s, err := ParseSchema([]byte(testSchema))
		if err != nil {
			t.Fatalf("ParseSchema(testSchema) = %v, want nil", err)
		}
		d, err := ParseString(`<root id="x"/>`)
		if err != nil {
			s.Free()
			t.Fatalf("ParseString(<root id=\"x\"/>) = %v, want nil", err)
		}
		defer d.Free()

		s.Free()
		s.Free()

		var sve SchemaValidationError
		err = s.Validate(d)
		if !errors.As(err, &sve) {
			t.Fatalf("Validate after Schema.Free() = %v, want SchemaValidationError", err)
		}
		if got := sve.Errors(); len(got) != 1 || got[0].Error() != "invalid schema" {
			t.Errorf("Validate after Schema.Free() details = %v, want [invalid schema]", got)
		}
	})

	t.Run("double_free_and_validate_after_document_free", func(t *testing.T) {
		s, err := ParseSchema([]byte(testSchema))
		if err != nil {
			t.Fatalf("ParseSchema(testSchema) = %v, want nil", err)
		}
		defer s.Free()

		d, err := ParseString(`<root id="x"/>`)
		if err != nil {
			t.Fatalf("ParseString(<root id=\"x\"/>) = %v, want nil", err)
		}
		d.Free()
		d.Free()

		var sve SchemaValidationError
		err = s.Validate(d)
		if !errors.As(err, &sve) {
			t.Fatalf("Validate after Document.Free() = %v, want SchemaValidationError", err)
		}
		if got := sve.Errors(); len(got) != 1 || got[0].Error() != "invalid document" {
			t.Errorf("Validate after Document.Free() details = %v, want [invalid document]", got)
		}
	})
}

// TestConcurrentValidate exercises concurrent ParseSchema, ParseString,
// Validate, and Free across goroutines.
func TestConcurrentValidate(t *testing.T) {
	const workers = 16
	const iters = 25

	var wg sync.WaitGroup
	wg.Add(workers)
	for g := 0; g < workers; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				s, err := ParseSchema([]byte(testSchema))
				if err != nil {
					t.Errorf("worker %d iter %d: ParseSchema(testSchema) = %v, want nil", id, i, err)
					return
				}
				validDoc, err := ParseString(`<root id="ok"/>`)
				if err != nil {
					s.Free()
					t.Errorf("worker %d iter %d: ParseString(valid) = %v, want nil", id, i, err)
					return
				}
				if err := s.Validate(validDoc); err != nil {
					t.Errorf("worker %d iter %d: Validate(valid) = %v, want nil", id, i, err)
				}
				validDoc.Free()

				badDoc, err := ParseString(`<root/>`)
				if err != nil {
					s.Free()
					t.Errorf("worker %d iter %d: ParseString(bad) = %v, want nil", id, i, err)
					return
				}
				if err := s.Validate(badDoc); err == nil {
					t.Errorf("worker %d iter %d: Validate(bad) = nil, want error", id, i)
				}
				badDoc.Free()
				s.Free()
			}
		}(g)
	}
	wg.Wait()
}

// TestRepeat runs parse, validate and free many times. Run it under
// `go test -asan` to check for leaks, double frees and use after free.
func TestRepeat(t *testing.T) {
	for i := 0; i < 200; i++ {
		s, err := ParseSchema([]byte(testSchema))
		if err != nil {
			t.Fatalf("iter %d: ParseSchema(testSchema) = %v, want nil", i, err)
		}
		d, err := ParseString(`<root/>`)
		if err != nil {
			s.Free()
			t.Fatalf("iter %d: ParseString(<root/>) = %v, want nil", i, err)
		}
		if err := s.Validate(d); err == nil {
			t.Fatalf("iter %d: Validate(<root/>) = nil, want error", i)
		}
		d.Free()
		s.Free()
		if _, err := ParseSchema([]byte("<root/>")); err == nil {
			t.Fatalf("iter %d: ParseSchema(<root/>) = nil, want error", i)
		}
	}
}
