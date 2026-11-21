package tl

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var ErrSchema = errors.New("gtg: invalid TL schema")
var ErrLimit = errors.New("gtg: TL decode limit exceeded")

type Limits struct {
	MaxInput  int
	MaxBytes  int
	MaxVector int
	MaxDepth  int
}

func DefaultLimits() Limits {
	return Limits{MaxInput: 32 << 20, MaxBytes: 16 << 20, MaxVector: 1 << 20, MaxDepth: 64}
}

func (x Limits) normalized() (Limits, bool) {
	if x.MaxInput == 0 && x.MaxBytes == 0 && x.MaxVector == 0 && x.MaxDepth == 0 {
		return DefaultLimits(), true
	}
	if x.MaxInput < 4 || x.MaxBytes < 0 || x.MaxVector < 0 || x.MaxDepth < 1 || x.MaxBytes > x.MaxInput {
		return Limits{}, false
	}
	return x, true
}

type Field struct {
	Name string
	Type string
	Flag int
}

type Declaration struct {
	Name        string
	Constructor uint32
	Result      string
	Fields      []Field
	Function    bool
}

type Schema struct {
	byName        map[string]Declaration
	byConstructor map[uint32]Declaration
	byResult      map[string][]Declaration
	declarations  []Declaration
}

func Build(input []Declaration) (*Schema, error) {
	if len(input) == 0 {
		return nil, ErrSchema
	}
	result := &Schema{byName: make(map[string]Declaration, len(input)), byConstructor: make(map[uint32]Declaration, len(input)), byResult: make(map[string][]Declaration)}
	result.declarations = make([]Declaration, len(input))
	for index, declaration := range input {
		if !validDeclaration(declaration) {
			return nil, fmt.Errorf("%w: invalid %s", ErrSchema, declaration.Name)
		}
		if _, exists := result.byName[declaration.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate name %s", ErrSchema, declaration.Name)
		}
		if _, exists := result.byConstructor[declaration.Constructor]; exists {
			return nil, fmt.Errorf("%w: duplicate constructor %08x", ErrSchema, declaration.Constructor)
		}
		declaration.Fields = append([]Field(nil), declaration.Fields...)
		result.declarations[index] = declaration
		result.byName[declaration.Name] = declaration
		result.byConstructor[declaration.Constructor] = declaration
		result.byResult[declaration.Result] = append(result.byResult[declaration.Result], declaration)
	}
	for name := range result.byResult {
		sort.Slice(result.byResult[name], func(left, right int) bool {
			return result.byResult[name][left].Name < result.byResult[name][right].Name
		})
	}
	return result, nil
}

func (x *Schema) Declaration(name string) (Declaration, bool) {
	if x == nil {
		return Declaration{}, false
	}
	value, ok := x.byName[name]
	return value, ok
}

func (x *Schema) Constructor(value uint32) (Declaration, bool) {
	if x == nil {
		return Declaration{}, false
	}
	result, ok := x.byConstructor[value]
	return result, ok
}

func (x *Schema) Result(name string) []Declaration {
	if x == nil {
		return nil
	}
	return append([]Declaration(nil), x.byResult[name]...)
}

func (x *Schema) Declarations() []Declaration {
	if x == nil {
		return nil
	}
	return append([]Declaration(nil), x.declarations...)
}

func validDeclaration(value Declaration) bool {
	if value.Name == "" || value.Result == "" || strings.ContainsAny(value.Name, " \t\r\n") || strings.ContainsAny(value.Result, "\r\n") {
		return false
	}
	for _, field := range value.Fields {
		if field.Name == "" || field.Type == "" || strings.ContainsAny(field.Name, " \t\r\n") || strings.ContainsAny(field.Type, "\r\n") || field.Flag < -1 || field.Flag > 31 {
			return false
		}
		if field.Type == "#" && field.Flag != -1 {
			return false
		}
	}
	return true
}
