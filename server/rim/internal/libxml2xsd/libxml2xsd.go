// Copyright (c) 2015 lestrrat
// Copyright 2026 Google LLC
//
// Use of this source code is governed by the MIT license found in the
// LICENSE file in this directory.

// Package libxml2xsd validates an XML document against an XML Schema (XSD)
// with the libxml2 C library.
//
// It is a minimal copy of the parts of github.com/lestrrat-go/libxml2 (MIT,
// see LICENSE) that server/rim uses: xsd.Parse, libxml2.ParseString and
// (*xsd.Schema).Validate. It makes the same libxml2 calls in the same order
// and returns the same error strings, so callers see no change in behavior.
//
// Differences from the upstream code, none of which changes a result or an
// error string:
//   - It does not call xmlParseInNodeContext, whose prototype changed in
//     libxml2 2.14 and breaks the upstream build against newer libxml2.
//   - The error accumulator does not read past the end of a message buffer,
//     checks for NULL, and frees each warning (upstream freed each error
//     twice instead).
//   - The schema parser context and the parsed schema document are freed.
//     Upstream leaked both on every Parse call.
package libxml2xsd

/*
#cgo pkg-config: libxml-2.0
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlschemas.h>

static inline xmlError* MY_xmlCtxtLastError(void *ctx) {
	return (xmlError*) xmlCtxtGetLastError(ctx);
}

#define GO_LIBXML2_ERRWARN_ACCUMULATOR_SIZE 32
typedef struct go_libxml2_errwarn_accumulator {
	char *errors[GO_LIBXML2_ERRWARN_ACCUMULATOR_SIZE];
	char *warnings[GO_LIBXML2_ERRWARN_ACCUMULATOR_SIZE];
	int erridx;
	int warnidx;
} go_libxml2_errwarn_accumulator;

static
go_libxml2_errwarn_accumulator*
MY_createErrWarnAccumulator() {
	int i;
	go_libxml2_errwarn_accumulator *ctx;
	ctx = (go_libxml2_errwarn_accumulator *) malloc(sizeof(go_libxml2_errwarn_accumulator));
	if (ctx == NULL) {
		return NULL;
	}
	for (i = 0; i < GO_LIBXML2_ERRWARN_ACCUMULATOR_SIZE; i++) {
		ctx->errors[i] = NULL;
		ctx->warnings[i] = NULL;
	}
	ctx->erridx = 0;
	ctx->warnidx = 0;
	return ctx;
}

static
void
MY_freeErrWarnAccumulator(go_libxml2_errwarn_accumulator* ctx) {
	int i = 0;
	if (ctx == NULL) {
		return;
	}
	for (i = 0; i < GO_LIBXML2_ERRWARN_ACCUMULATOR_SIZE; i++) {
		if (ctx->errors[i] != NULL) {
			free(ctx->errors[i]);
		}
		if (ctx->warnings[i] != NULL) {
			free(ctx->warnings[i]);
		}
	}
	free(ctx);
}

static
void
MY_accumulateErr(void *ctx, const char *msg, ...) {
	char buf[1024];
	va_list args;
	go_libxml2_errwarn_accumulator *accum;
	int len;

	accum = (go_libxml2_errwarn_accumulator *) ctx;
	if (accum == NULL || accum->erridx < 0 || accum->erridx >= GO_LIBXML2_ERRWARN_ACCUMULATOR_SIZE) {
		return;
	}

	va_start(args, msg);
	len = vsnprintf(buf, sizeof(buf), msg, args);
	va_end(args);

	if (len <= 0) {
		return;
	}
	if ((size_t) len >= sizeof(buf)) {
		len = sizeof(buf) - 1;
	}

	if (buf[len-1] == '\n') {
		// don't want newlines in my error values
		buf[len-1] = '\0';
		len--;
	}
	char *out = (char *) calloc((size_t) len + 1, sizeof(char));
	if (out == NULL) {
		return;
	}
	if (len > 0) {
		memcpy(out, buf, (size_t) len);
	}
	out[len] = '\0';

	int i = accum->erridx++;
	accum->errors[i] = out;
}

static
void
MY_setErrWarnAccumulator(xmlSchemaValidCtxtPtr ctxt, go_libxml2_errwarn_accumulator *accum) {
	xmlSchemaSetValidErrors(ctxt, MY_accumulateErr, NULL, accum);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// libxml2 asks multithreaded programs to call xmlInitParser once before
// any other use; older versions (such as 2.9.x) initialize lazily and not
// thread-safely otherwise. Upstream did not do this; it changes no result.
func init() {
	C.xmlInitParser()
}

// Schema is a parsed XML Schema. Call Free when done with it.
type Schema struct {
	ptr *C.xmlSchema
	// doc is the schema document. The schema refers to it, and libxml2 does
	// not free it in xmlSchemaFree, so Free frees it after the schema.
	doc *C.xmlDoc
}

// Document is a parsed XML document. Call Free when done with it.
type Document struct {
	ptr *C.xmlDoc
}

// SchemaValidationError is returned by Validate when the document does not
// match the schema. Errors returns the libxml2 messages.
type SchemaValidationError struct {
	errors []error
}

// Error implements the error interface. Like upstream, it does not include
// the libxml2 messages.
func (sve SchemaValidationError) Error() string {
	return "schema validation failed"
}

// Errors returns the libxml2 messages, at most 32.
func (sve SchemaValidationError) Errors() []error {
	return sve.errors
}

// xmlCtxtLastError formats the last error of a parser context the same way
// as upstream clib.xmlCtxtLastErrorRaw.
func xmlCtxtLastError(ctx *C.xmlParserCtxt) error {
	e := C.MY_xmlCtxtLastError(unsafe.Pointer(ctx))
	if e == nil {
		return errors.New(`unknown error`)
	}
	msg := strings.TrimSuffix(C.GoString(e.message), "\n")
	return fmt.Errorf("Entity: line %v: parser error : %v", e.line, msg)
}

// ParseSchema parses an XML Schema document. It matches upstream xsd.Parse
// with no options.
func ParseSchema(buf []byte) (*Schema, error) {
	s, err := parseSchema(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to parse input: %v", err)
	}
	return s, nil
}

// parseSchema matches upstream clib.XMLSchemaParse with no options.
func parseSchema(buf []byte) (*Schema, error) {
	// Upstream indexes buf[0] and so panics on an empty buffer. Keep that
	// behavior: callers have never seen an error for this case.
	cbuf := (*C.char)(unsafe.Pointer(&buf[0]))

	docctx := C.xmlCreateMemoryParserCtxt(cbuf, C.int(len(buf)))
	if docctx == nil {
		return nil, errors.New("error creating doc parser")
	}
	// The parsed document does not depend on docctx.
	defer C.xmlFreeParserCtxt(docctx)

	doc := C.xmlCtxtReadMemory(docctx, cbuf, C.int(len(buf)), nil, nil, 0)
	if doc == nil {
		return nil, fmt.Errorf("failed to read schema from memory: %v", xmlCtxtLastError(docctx))
	}

	parserCtx := C.xmlSchemaNewDocParserCtxt(doc)
	if parserCtx == nil {
		C.xmlFreeDoc(doc)
		return nil, errors.New("failed to create parser")
	}
	s := C.xmlSchemaParse(parserCtx)
	C.xmlSchemaFreeParserCtxt(parserCtx)
	if s == nil {
		C.xmlFreeDoc(doc)
		return nil, errors.New("failed to parse schema")
	}
	return &Schema{ptr: s, doc: doc}, nil
}

// Free releases the schema and its document.
func (s *Schema) Free() {
	if s == nil || s.ptr == nil {
		return
	}
	C.xmlSchemaFree(s.ptr)
	s.ptr = nil
	if s.doc != nil {
		C.xmlFreeDoc(s.doc)
		s.doc = nil
	}
}

// ParseString parses an XML document. It matches upstream libxml2.ParseString
// with no options.
func ParseString(s string) (*Document, error) {
	cs := C.CString(s)
	ctx := C.xmlCreateMemoryParserCtxt(cs, C.int(len(s)))
	C.free(unsafe.Pointer(cs))
	if ctx == nil {
		return nil, errors.New("failed to create parse context: failed to execute XMLCreateMemoryParserCtxt: error creating parser")
	}
	defer C.xmlFreeParserCtxt(ctx)
	C.xmlCtxtUseOptions(ctx, 0)

	var cfile *C.char
	if s != "" {
		cfile = C.CString(s)
		defer C.free(unsafe.Pointer(cfile))
	}
	doc := C.xmlCtxtReadMemory(ctx, cfile, C.int(len(s)), nil, nil, 0)
	if doc == nil {
		return nil, fmt.Errorf("failed to create parse input: failed to read document from memory: %v", xmlCtxtLastError(ctx))
	}
	return &Document{ptr: doc}, nil
}

// Free releases the document.
func (d *Document) Free() {
	if d == nil || d.ptr == nil {
		return
	}
	C.xmlFreeDoc(d.ptr)
	d.ptr = nil
}

// Validate validates d against s. It returns nil or a SchemaValidationError.
// It matches upstream (*xsd.Schema).Validate with no options.
func (s *Schema) Validate(d *Document) error {
	if errs := validate(s, d); errs != nil {
		return SchemaValidationError{errors: errs}
	}
	return nil
}

// validate matches upstream clib.XMLSchemaValidateDocument.
func validate(s *Schema, d *Document) []error {
	if s == nil || s.ptr == nil {
		return []error{errors.New("invalid schema")}
	}
	if d == nil || d.ptr == nil {
		return []error{errors.New("invalid document")}
	}

	ctx := C.xmlSchemaNewValidCtxt(s.ptr)
	if ctx == nil {
		return []error{errors.New("failed to build validator")}
	}
	defer C.xmlSchemaFreeValidCtxt(ctx)

	accum := C.MY_createErrWarnAccumulator()
	if accum == nil {
		return []error{errors.New("failed to allocate error accumulator")}
	}
	defer C.MY_freeErrWarnAccumulator(accum)

	C.MY_setErrWarnAccumulator(ctx, accum)

	if C.xmlSchemaValidateDoc(ctx, d.ptr) == 0 {
		return nil
	}

	errs := make([]error, accum.erridx)
	for i := 0; i < int(accum.erridx); i++ {
		errs[i] = errors.New(C.GoString(accum.errors[i]))
	}
	return errs
}
