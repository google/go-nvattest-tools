package testing

import (
	"testing"

	"github.com/beevik/etree"
	testdata "github.com/google/go-nvattest-tools/testing/testdata"
)

// ParseXML is a helper function to parse an XML file for the test cases.
func ParseXML(t *testing.T, xmlFilePath string) *etree.Element {
	t.Helper()
	xmlBytes, err := testdata.ReadXMLFile(xmlFilePath)
	if err != nil {
		t.Fatalf("Failed to read XML file: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatalf("Failed to parse XML bytes: %v", err)
	}
	return doc.Root()
}
