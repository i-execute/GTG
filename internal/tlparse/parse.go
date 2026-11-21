package tlparse

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/i-execute/GTG/tl"
)

var ErrParse = errors.New("gtg: invalid TL schema source")

func Parse(source []byte) ([]tl.Declaration, error) {
	lines := strings.Split(string(source), "\n")
	function := false
	result := make([]tl.Declaration, 0, len(lines))
	for lineNumber, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//") {
			candidate := strings.TrimSpace(strings.TrimPrefix(line, "//"))
			if strings.HasSuffix(candidate, ";") && strings.Contains(candidate, "=") {
				line = candidate
			} else {
				continue
			}
		} else {
			line = strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
		}
		if line == "" {
			continue
		}
		if line == "---functions---" {
			function = true
			continue
		}
		if line == "---types---" {
			function = false
			continue
		}
		if !strings.HasSuffix(line, ";") || !strings.Contains(line, "=") {
			continue
		}
		words := strings.Fields(line)
		if len(words) == 0 || !strings.Contains(words[0], "#") {
			continue
		}
		declaration, err := parseLine(strings.TrimSuffix(line, ";"), function)
		if err != nil {
			return nil, fmt.Errorf("%w at line %d", err, lineNumber+1)
		}
		result = append(result, declaration)
	}
	if len(result) == 0 {
		return nil, ErrParse
	}
	return deduplicate(result), nil
}

func deduplicate(input []tl.Declaration) []tl.Declaration {
	indexes := make(map[uint32]int, len(input))
	result := make([]tl.Declaration, 0, len(input))
	for _, declaration := range input {
		index, exists := indexes[declaration.Constructor]
		if !exists {
			indexes[declaration.Constructor] = len(result)
			result = append(result, declaration)
			continue
		}
		current := result[index]
		if (declaration.Function && !current.Function) || len(declaration.Fields) > len(current.Fields) {
			result[index] = declaration
		}
	}
	return result
}

func parseLine(line string, function bool) (tl.Declaration, error) {
	var result tl.Declaration
	pieces := strings.SplitN(line, "=", 2)
	if len(pieces) != 2 {
		return result, ErrParse
	}
	left := strings.Fields(strings.TrimSpace(pieces[0]))
	resultName := strings.TrimSpace(pieces[1])
	if len(left) == 0 || resultName == "" {
		return result, ErrParse
	}
	nameParts := strings.SplitN(left[0], "#", 2)
	if len(nameParts) != 2 || nameParts[0] == "" || len(nameParts[1]) == 0 || len(nameParts[1]) > 8 {
		return result, ErrParse
	}
	constructor, err := strconv.ParseUint(nameParts[1], 16, 32)
	if err != nil {
		return result, ErrParse
	}
	result.Name = nameParts[0]
	result.Constructor = uint32(constructor)
	result.Result = resultName
	result.Function = function
	for _, token := range left[1:] {
		if strings.HasPrefix(token, "{") && strings.HasSuffix(token, "}") {
			continue
		}
		if token == "#" || token == "[" || token == "]" || token == "t" {
			continue
		}
		fieldParts := strings.SplitN(token, ":", 2)
		if len(fieldParts) != 2 || fieldParts[0] == "" || fieldParts[1] == "" {
			return tl.Declaration{}, ErrParse
		}
		field := tl.Field{Name: fieldParts[0], Type: fieldParts[1], Flag: -1}
		if offset := strings.IndexByte(field.Type, '?'); offset > 0 {
			prefix := field.Type[:offset]
			prefixParts := strings.Split(prefix, ".")
			if len(prefixParts) != 2 || prefixParts[0] == "" {
				return tl.Declaration{}, ErrParse
			}
			flag, err := strconv.Atoi(prefixParts[1])
			if err != nil || flag < 0 || flag > 31 {
				return tl.Declaration{}, ErrParse
			}
			field.Flag = flag
		}
		result.Fields = append(result.Fields, field)
	}
	return result, nil
}
