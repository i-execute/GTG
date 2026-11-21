package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/i-execute/GTG/internal/tlparse"
	"github.com/i-execute/GTG/tl"
)

type sourceLock struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}

type lock struct {
	SchemaRevision string       `json:"schema_revision"`
	Layer          int          `json:"layer"`
	Schemas        []sourceLock `json:"schemas"`
}

func main() {
	layerFlag := flag.String("layer", "", "\"latest\" or a TDLib commit to fetch the schema, verify, pin, and regenerate")
	lockPath := flag.String("lock", "schema/telegram.lock.json", "")
	input := flag.String("input", "", "")
	output := flag.String("out", "internal/tlgen/registry_generated.go", "")
	typesOutput := flag.String("types-out", "", "")
	publicOutput := flag.String("public-out", "telegram/types_generated.go", "")
	flag.Parse()
	if *layerFlag != "" {
		if err := runLayerUpdate(*layerFlag, *lockPath, *output, *typesOutput, *publicOutput); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := generateWithPublic(*lockPath, *input, *output, *typesOutput, *publicOutput); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runLayerUpdate(target, lockPath, output, typesOutput, publicOutput string) error {
	manifest, err := readLock(lockPath)
	if err != nil {
		return err
	}
	commit, layer, err := resolveLayer(target)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(manifest.Schemas))
	inputPaths := make([]string, 0, len(manifest.Schemas))
	digests := make([]string, 0, len(manifest.Schemas))
	directory, err := os.MkdirTemp("", "gtg-schema-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	for _, item := range manifest.Schemas {
		data, err := fetchSchema(commit, item.Name)
		if err != nil {
			return err
		}
		digest := schemaDigest(data)
		path := filepath.Join(directory, item.Name+".tl")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return err
		}
		names = append(names, item.Name)
		inputPaths = append(inputPaths, path)
		digests = append(digests, digest)
	}
	if err := writeUpdatedLock(lockPath, commit, layer, digests, names); err != nil {
		return err
	}
	return generateWithPublic(lockPath, strings.Join(inputPaths, ","), output, typesOutput, publicOutput)
}

func generate(lockPath, input, output, typesOutput string) error {
	return generateWithPublic(lockPath, input, output, typesOutput, "")
}

func generateWithPublic(lockPath, input, output, typesOutput, publicOutput string) error {
	manifest, err := readLock(lockPath)
	if err != nil {
		return err
	}
	inputs, err := splitInputs(input, len(manifest.Schemas))
	if err != nil {
		return err
	}
	declarations := make([]tl.Declaration, 0, 2048)
	combined := sha256.New()
	for index, item := range manifest.Schemas {
		source, err := readSource(item.Source, inputs[index])
		if err != nil {
			return err
		}
		digest := sha256.Sum256(source)
		if hex.EncodeToString(digest[:]) != item.SHA256 {
			clear(source)
			return fmt.Errorf("gtg: schema digest mismatch for %s", item.Name)
		}
		_, _ = combined.Write(digest[:])
		parsed, err := tlparse.Parse(source)
		clear(source)
		if err != nil {
			return err
		}
		declarations = append(declarations, parsed...)
	}
	if _, err := tl.Build(declarations); err != nil {
		return err
	}
	digest := hex.EncodeToString(combined.Sum(nil))
	generated, err := render(manifest, digest, declarations)
	if err != nil {
		return err
	}
	formatted, err := format.Source(generated)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(output, formatted, 0o644); err != nil {
		return err
	}
	if typesOutput == "" {
		typesOutput = generatedTypesPath(output)
	}
	types, err := renderTypes(declarations)
	if err != nil {
		return err
	}
	formattedTypes, err := format.Source(types)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(typesOutput), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(typesOutput, formattedTypes, 0o644); err != nil {
		return err
	}
	if publicOutput == "" {
		return nil
	}
	public, err := renderPublicTypes(declarations)
	if err != nil {
		return err
	}
	formattedPublic, err := format.Source(public)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(publicOutput), 0o755); err != nil {
		return err
	}
	return os.WriteFile(publicOutput, formattedPublic, 0o644)
}

func generatedTypesPath(output string) string {
	directory := filepath.Dir(output)
	base := filepath.Base(output)
	if base == "registry_generated.go" {
		return filepath.Join(directory, "types_generated.go")
	}
	return filepath.Join(directory, strings.TrimSuffix(base, filepath.Ext(base))+"_types.go")
}

func readLock(path string) (lock, error) {
	var result lock
	data, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	if err != nil || len(result.SchemaRevision) != 40 || result.Layer <= 0 || len(result.Schemas) == 0 {
		return lock{}, fmt.Errorf("gtg: invalid schema lock")
	}
	seen := make(map[string]struct{}, len(result.Schemas))
	for _, item := range result.Schemas {
		if item.Name == "" || item.Source == "" || len(item.SHA256) != 64 {
			return lock{}, fmt.Errorf("gtg: invalid schema lock")
		}
		if _, exists := seen[item.Name]; exists {
			return lock{}, fmt.Errorf("gtg: invalid schema lock")
		}
		seen[item.Name] = struct{}{}
	}
	return result, nil
}

func splitInputs(input string, count int) ([]string, error) {
	if input == "" {
		return make([]string, count), nil
	}
	values := strings.Split(input, ",")
	if len(values) != count {
		return nil, fmt.Errorf("gtg: input count does not match schema lock")
	}
	return values, nil
}

func readSource(location, input string) ([]byte, error) {
	if input == "" {
		return nil, fmt.Errorf("gtg: schema input required for %s", location)
	}
	return os.ReadFile(input)
}

func render(manifest lock, digest string, declarations []tl.Declaration) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("package tlgen\n\n")
	out.WriteString("import (\n\t\"sync\"\n\n\t\"github.com/i-execute/GTG/tl\"\n)\n\n")
	out.WriteString("const SchemaSHA256 = ")
	out.WriteString(strconv.Quote(digest))
	out.WriteString("\n")
	out.WriteString("const SchemaRevision = ")
	out.WriteString(strconv.Quote(manifest.SchemaRevision))
	out.WriteString("\n")
	out.WriteString("const Layer = ")
	out.WriteString(strconv.Itoa(manifest.Layer))
	out.WriteString("\n\nvar schemaOnce sync.Once\nvar schemaValue *tl.Schema\n\n")
	out.WriteString("func Schema() *tl.Schema {\n\tschemaOnce.Do(func() {\n\t\tvar err error\n\t\tschemaValue, err = tl.Build(declarations)\n\t\tif err != nil { panic(err) }\n\t})\n\treturn schemaValue\n}\n\n")
	out.WriteString("var declarations = []tl.Declaration{\n")
	for _, declaration := range declarations {
		out.WriteString("{Name:")
		out.WriteString(strconv.Quote(declaration.Name))
		out.WriteString(", Constructor:")
		out.WriteString(fmt.Sprintf("0x%08x", declaration.Constructor))
		out.WriteString(", Result:")
		out.WriteString(strconv.Quote(declaration.Result))
		out.WriteString(", Function:")
		out.WriteString(strconv.FormatBool(declaration.Function))
		if len(declaration.Fields) != 0 {
			out.WriteString(", Fields:[]tl.Field{")
			for _, field := range declaration.Fields {
				out.WriteString("{Name:")
				out.WriteString(strconv.Quote(field.Name))
				out.WriteString(", Type:")
				out.WriteString(strconv.Quote(field.Type))
				out.WriteString(", Flag:")
				out.WriteString(strconv.Itoa(field.Flag))
				out.WriteString("},")
			}
			out.WriteString("}")
		}
		out.WriteString("},\n")
	}
	out.WriteString("}\n\n")
	results := make(map[string]struct{})
	for _, declaration := range declarations {
		results[declaration.Result] = struct{}{}
	}
	names := make([]string, 0, len(results))
	for name := range results {
		names = append(names, name)
	}
	sort.Strings(names)
	out.WriteString("var Types = []string{")
	for _, name := range names {
		out.WriteString(strconv.Quote(name))
		out.WriteString(",")
	}
	out.WriteString("}\n")
	return out.Bytes(), nil
}

func renderTypes(declarations []tl.Declaration) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("package tlgen\n\n")
	out.WriteString("import \"github.com/i-execute/GTG/tl\"\n\n")
	for _, declaration := range declarations {
		name := generatedTypeName(declaration)
		out.WriteString("type ")
		out.WriteString(name)
		out.WriteString(" struct {\n")
		fieldNames := make([]string, len(declaration.Fields))
		used := make(map[string]int, len(declaration.Fields))
		for index, field := range declaration.Fields {
			fieldName := generatedFieldName(field.Name, index)
			if used[fieldName] != 0 {
				fieldName += strconv.Itoa(index + 1)
			}
			used[fieldName]++
			fieldNames[index] = fieldName
			out.WriteString(fieldName)
			out.WriteByte(' ')
			out.WriteString(generatedFieldType(field))
			out.WriteByte('\n')
		}
		out.WriteString("}\n\n")
		out.WriteString("func New")
		out.WriteString(name)
		out.WriteString("() ")
		out.WriteString(name)
		out.WriteString(" { return ")
		out.WriteString(name)
		out.WriteString("{} }\n\n")
		out.WriteString("func (x ")
		out.WriteString(name)
		out.WriteString(") Dynamic() tl.Dynamic {\n")
		out.WriteString("fields := make(map[string]any, ")
		out.WriteString(strconv.Itoa(len(declaration.Fields)))
		out.WriteString(")\n")
		for index, field := range declaration.Fields {
			fieldName := fieldNames[index]
			literal := strconv.Quote(field.Name)
			if field.Flag >= 0 {
				if bareGeneratedType(field.Type) == "true" {
					out.WriteString("if x.")
					out.WriteString(fieldName)
					out.WriteString(" { fields[")
					out.WriteString(literal)
					out.WriteString("] = true }\n")
				} else {
					out.WriteString("if x.")
					out.WriteString(fieldName)
					out.WriteString(" != nil { fields[")
					out.WriteString(literal)
					out.WriteString("] = *x.")
					out.WriteString(fieldName)
					out.WriteString(" }\n")
				}
			} else {
				out.WriteString("fields[")
				out.WriteString(literal)
				out.WriteString("] = x.")
				out.WriteString(fieldName)
				out.WriteByte('\n')
			}
		}
		out.WriteString("return tl.Dynamic{Name: ")
		out.WriteString(strconv.Quote(declaration.Name))
		out.WriteString(", Fields: fields}\n}\n\n")
		out.WriteString("func ")
		out.WriteString(name)
		out.WriteString("FromDynamic(value tl.Dynamic) (")
		out.WriteString(name)
		out.WriteString(", bool) {\n")
		out.WriteString("if value.Name != ")
		out.WriteString(strconv.Quote(declaration.Name))
		out.WriteString(" { return ")
		out.WriteString(name)
		out.WriteString("{}, false }\n")
		out.WriteString("var result ")
		out.WriteString(name)
		out.WriteByte('\n')
		for index, field := range declaration.Fields {
			fieldName := fieldNames[index]
			base := generatedBaseType(field.Type)
			literal := strconv.Quote(field.Name)
			out.WriteString("{\n")
			if field.Flag >= 0 {
				if bareGeneratedType(field.Type) == "true" {
					out.WriteString("if raw, ok := value.Fields[")
					out.WriteString(literal)
					out.WriteString("]; ok { typed, ok := raw.(bool); if !ok { return ")
					out.WriteString(name)
					out.WriteString("{}, false }; result.")
					out.WriteString(fieldName)
					out.WriteString(" = typed }\n")
				} else if base == "any" {
					out.WriteString("if raw, ok := value.Fields[")
					out.WriteString(literal)
					out.WriteString("]; ok { result.")
					out.WriteString(fieldName)
					out.WriteString(" = &raw }\n")
				} else {
					out.WriteString("if raw, ok := value.Fields[")
					out.WriteString(literal)
					out.WriteString("]; ok { typed, ok := raw.(")
					out.WriteString(base)
					out.WriteString("); if !ok { return ")
					out.WriteString(name)
					out.WriteString("{}, false }; result.")
					out.WriteString(fieldName)
					out.WriteString(" = &typed }\n")
				}
			} else if base == "any" {
				out.WriteString("raw, ok := value.Fields[")
				out.WriteString(literal)
				out.WriteString("]; if !ok { return ")
				out.WriteString(name)
				out.WriteString("{}, false }; result.")
				out.WriteString(fieldName)
				out.WriteString(" = raw\n")
			} else {
				out.WriteString("raw, ok := value.Fields[")
				out.WriteString(literal)
				out.WriteString("]; if !ok { return ")
				out.WriteString(name)
				out.WriteString("{}, false }; typed, ok := raw.(")
				out.WriteString(base)
				out.WriteString("); if !ok { return ")
				out.WriteString(name)
				out.WriteString("{}, false }; result.")
				out.WriteString(fieldName)
				out.WriteString(" = typed\n")
			}
			out.WriteString("}\n")
		}
		out.WriteString("return result, true\n}\n\n")
		if declaration.Function {
			out.WriteString("func (x ")
			out.WriteString(name)
			out.WriteString(") Request() tl.Dynamic { return x.Dynamic() }\n\n")
		}
	}
	return out.Bytes(), nil
}

func renderPublicTypes(declarations []tl.Declaration) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("package telegram\n\n")
	out.WriteString("import (\n\tinternal \"github.com/i-execute/GTG/internal/tlgen\"\n\t\"github.com/i-execute/GTG/tl\"\n)\n\n")
	out.WriteString("const SchemaSHA256 = internal.SchemaSHA256\n")
	out.WriteString("const SchemaRevision = internal.SchemaRevision\n")
	out.WriteString("const Layer = internal.Layer\n\n")
	out.WriteString("type Dynamic = tl.Dynamic\n")
	out.WriteString("type Unknown = tl.Unknown\n")
	out.WriteString("type Limits = tl.Limits\n\n")
	out.WriteString("func Schema() *tl.Schema { return internal.Schema() }\n")
	out.WriteString("func DefaultLimits() Limits { return tl.DefaultLimits() }\n\n")
	for _, declaration := range declarations {
		name := generatedTypeName(declaration)
		out.WriteString("type ")
		out.WriteString(name)
		out.WriteString(" = internal.")
		out.WriteString(name)
		out.WriteString("\n\nfunc New")
		out.WriteString(name)
		out.WriteString("() ")
		out.WriteString(name)
		out.WriteString(" { return internal.New")
		out.WriteString(name)
		out.WriteString("() }\n\nfunc ")
		out.WriteString(name)
		out.WriteString("FromDynamic(value Dynamic) (")
		out.WriteString(name)
		out.WriteString(", bool) { return internal.")
		out.WriteString(name)
		out.WriteString("FromDynamic(value) }\n\n")
	}
	return out.Bytes(), nil
}

func generatedTypeName(declaration tl.Declaration) string {
	prefix := "Constructor"
	if declaration.Function {
		prefix = "Method"
	}
	return prefix + generatedIdentifier(declaration.Name) + "_" + fmt.Sprintf("%08X", declaration.Constructor)
}

func generatedFieldName(name string, index int) string {
	return "F" + generatedIdentifier(name) + strconv.Itoa(index+1)
}

func generatedIdentifier(value string) string {
	var out strings.Builder
	upper := true
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' {
			if upper {
				character -= 'a' - 'A'
			}
			out.WriteByte(character)
			upper = false
			continue
		}
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			out.WriteByte(character)
			upper = false
			continue
		}
		upper = true
	}
	if out.Len() == 0 {
		return "Value"
	}
	return out.String()
}

func generatedFieldType(field tl.Field) string {
	base := generatedBaseType(field.Type)
	if field.Flag >= 0 && bareGeneratedType(field.Type) != "true" {
		return "*" + base
	}
	return base
}

func generatedBaseType(value string) string {
	bare := bareGeneratedType(value)
	switch bare {
	case "#", "int":
		return "int32"
	case "long":
		return "int64"
	case "double":
		return "float64"
	case "string":
		return "string"
	case "bytes", "int128", "int256":
		return "[]byte"
	case "true":
		return "bool"
	}
	if strings.HasPrefix(bare, "Vector<") || strings.HasPrefix(bare, "vector<") {
		return "[]any"
	}
	if strings.HasPrefix(value, "!") {
		return "any"
	}
	return "tl.Dynamic"
}

func bareGeneratedType(value string) string {
	if offset := strings.IndexByte(value, '?'); offset >= 0 {
		value = value[offset+1:]
	}
	value = strings.TrimPrefix(value, "!")
	value = strings.TrimPrefix(value, "%")
	return value
}
