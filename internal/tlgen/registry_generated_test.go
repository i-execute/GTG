package tlgen

import "testing"

func TestGeneratedRegistry(t *testing.T) {
	schema := Schema()
	if schema == nil || len(schema.Declarations()) < 1000 || SchemaSHA256 == "" || SchemaRevision == "" {
		t.Fatal("generated registry incomplete")
	}
	functions := 0
	for _, declaration := range schema.Declarations() {
		if declaration.Function {
			functions++
		}
	}
	if functions < 100 {
		t.Fatal("generated functions incomplete")
	}
}
