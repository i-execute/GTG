package tlparse

import "testing"

func TestParseFlagsFunctionsAndPrefixDeduplication(t *testing.T) {
	source := []byte("thing#aabbccdd flags:# enabled:flags.0?true name:flags.1?string = Thing;\n---functions---\ncallPrefix#01020304 token:string = Error;\ncall#01020304 {X:Type} token:string query:!X = X;\n")
	declarations, err := Parse(source)
	if err != nil || len(declarations) != 2 {
		t.Fatal(err)
	}
	if declarations[0].Name != "thing" || declarations[0].Fields[1].Flag != 0 || declarations[1].Name != "call" || !declarations[1].Function {
		t.Fatal("parse mismatch")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("node#01020304 value:int = Node;"))
	f.Fuzz(func(t *testing.T, source []byte) {
		_, _ = Parse(source)
	})
}
