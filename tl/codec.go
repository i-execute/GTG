package tl

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
)

var ErrCodec = errors.New("gtg: invalid TL value")

type Dynamic struct {
	Name   string
	Fields map[string]any
}

type Unknown struct {
	Constructor uint32
	Data        []byte
	Borrowed    bool
}

func (x Unknown) Clone() Unknown {
	x.Data = append([]byte(nil), x.Data...)
	x.Borrowed = false
	return x
}

func (x *Schema) Encode(value Dynamic) ([]byte, error) {
	if x == nil {
		return nil, ErrCodec
	}
	declaration, ok := x.Declaration(value.Name)
	if !ok {
		return nil, ErrCodec
	}
	out := encoder{}
	out.u32(declaration.Constructor)
	if err := x.encodeFields(&out, declaration, value.Fields); err != nil {
		clear(out.data)
		return nil, err
	}
	return out.data, nil
}

func (x *Schema) Decode(data []byte) (Dynamic, *Unknown, error) {
	return x.decode(data, DefaultLimits(), false)
}

func (x *Schema) DecodeWithLimits(data []byte, limits Limits) (Dynamic, *Unknown, error) {
	return x.decode(data, limits, false)
}

func (x *Schema) DecodeZeroCopy(data []byte) (Dynamic, *Unknown, error) {
	return x.decode(data, DefaultLimits(), true)
}

func (x *Schema) DecodeZeroCopyWithLimits(data []byte, limits Limits) (Dynamic, *Unknown, error) {
	return x.decode(data, limits, true)
}

func (x *Schema) decode(data []byte, limits Limits, borrowed bool) (Dynamic, *Unknown, error) {
	limits, ok := limits.normalized()
	if x == nil || !ok || len(data) < 4 {
		return Dynamic{}, nil, ErrCodec
	}
	if len(data) > limits.MaxInput {
		return Dynamic{}, nil, ErrLimit
	}
	in := decoder{data: data, limits: limits, borrowed: borrowed}
	constructor, err := in.u32()
	if err != nil {
		return Dynamic{}, nil, ErrCodec
	}
	declaration, ok := x.Constructor(constructor)
	if !ok {
		unknown := &Unknown{Constructor: constructor, Borrowed: borrowed}
		if borrowed {
			unknown.Data = data
		} else {
			unknown.Data = append([]byte(nil), data...)
		}
		return Dynamic{}, unknown, nil
	}
	value, err := x.decodeDeclared(&in, declaration)
	if err != nil {
		return Dynamic{}, nil, err
	}
	if in.remaining() != 0 {
		return Dynamic{}, nil, ErrCodec
	}
	return value, nil, nil
}

func (x *Schema) encodeFields(out *encoder, declaration Declaration, fields map[string]any) error {
	flags := make(map[string]uint32)
	for _, field := range declaration.Fields {
		if field.Type != "#" {
			continue
		}
		if supplied, ok := fields[field.Name]; ok {
			value, ok := unsigned(supplied)
			if !ok {
				return ErrCodec
			}
			flags[field.Name] = value
		} else {
			flags[field.Name] = 0
		}
	}
	for _, field := range declaration.Fields {
		if field.Flag < 0 {
			continue
		}
		flagName := optionalFlagName(field.Type)
		current, ok := flags[flagName]
		if !ok {
			return ErrCodec
		}
		_, present := fields[field.Name]
		if bareType(field.Type) == "true" {
			present = boolean(fields[field.Name])
		}
		if present {
			current |= 1 << field.Flag
		} else {
			current &^= 1 << field.Flag
		}
		flags[flagName] = current
	}
	for _, field := range declaration.Fields {
		if field.Type == "#" {
			out.u32(flags[field.Name])
			continue
		}
		if field.Flag >= 0 && flags[optionalFlagName(field.Type)]&(1<<field.Flag) == 0 {
			continue
		}
		if bareType(field.Type) == "true" {
			continue
		}
		value, ok := fields[field.Name]
		if !ok {
			return ErrCodec
		}
		if err := x.encodeType(out, bareType(field.Type), value); err != nil {
			return err
		}
	}
	return nil
}

func (x *Schema) encodeType(out *encoder, typeName string, value any) error {
	switch typeName {
	case "int":
		integer, ok := signed32(value)
		if !ok {
			return ErrCodec
		}
		out.u32(uint32(integer))
		return nil
	case "long":
		integer, ok := signed64(value)
		if !ok {
			return ErrCodec
		}
		out.u64(uint64(integer))
		return nil
	case "double":
		value, ok := value.(float64)
		if !ok {
			return ErrCodec
		}
		out.u64(math.Float64bits(value))
		return nil
	case "string":
		text, ok := value.(string)
		if !ok {
			return ErrCodec
		}
		out.bytes([]byte(text))
		return nil
	case "bytes":
		data, ok := value.([]byte)
		if !ok {
			return ErrCodec
		}
		out.bytes(data)
		return nil
	case "int128":
		return encodeFixed(out, value, 16)
	case "int256":
		return encodeFixed(out, value, 32)
	}
	if item, ok := vectorElement(typeName); ok {
		items, ok := value.([]any)
		if !ok {
			return ErrCodec
		}
		vector, ok := x.Declaration("vector")
		if !ok {
			return ErrCodec
		}
		out.u32(vector.Constructor)
		out.u32(uint32(len(items)))
		for _, value := range items {
			if err := x.encodeType(out, item, value); err != nil {
				return err
			}
		}
		return nil
	}
	object, ok := value.(Dynamic)
	if !ok {
		return ErrCodec
	}
	declaration, ok := x.Declaration(object.Name)
	if !ok {
		return ErrCodec
	}
	out.u32(declaration.Constructor)
	return x.encodeFields(out, declaration, object.Fields)
}

func (x *Schema) decodeDeclared(in *decoder, declaration Declaration) (Dynamic, error) {
	if !in.enter() {
		return Dynamic{}, ErrLimit
	}
	defer in.leave()
	result := Dynamic{Name: declaration.Name, Fields: make(map[string]any, len(declaration.Fields))}
	flags := make(map[string]uint32)
	for _, field := range declaration.Fields {
		if field.Type == "#" {
			value, err := in.u32()
			if err != nil {
				return Dynamic{}, ErrCodec
			}
			flags[field.Name] = value
			result.Fields[field.Name] = int32(value)
			continue
		}
		if field.Flag >= 0 && flags[optionalFlagName(field.Type)]&(1<<field.Flag) == 0 {
			continue
		}
		if bareType(field.Type) == "true" {
			result.Fields[field.Name] = true
			continue
		}
		value, unknown, err := x.decodeType(in, bareType(field.Type))
		if err != nil {
			return Dynamic{}, err
		}
		if unknown != nil {
			result.Fields[field.Name] = *unknown
		} else {
			result.Fields[field.Name] = value
		}
	}
	return result, nil
}

func (x *Schema) decodeType(in *decoder, typeName string) (any, *Unknown, error) {
	switch typeName {
	case "int":
		value, err := in.u32()
		return int32(value), nil, err
	case "long":
		value, err := in.u64()
		return int64(value), nil, err
	case "double":
		value, err := in.u64()
		return math.Float64frombits(value), nil, err
	case "string":
		value, err := in.bytes()
		return string(value), nil, err
	case "bytes":
		value, err := in.bytes()
		if err != nil {
			return nil, nil, err
		}
		if in.borrowed {
			return value, nil, nil
		}
		return append([]byte(nil), value...), nil, nil
	case "int128":
		return in.fixed(16)
	case "int256":
		return in.fixed(32)
	}
	if item, ok := vectorElement(typeName); ok {
		constructor, err := in.u32()
		if err != nil {
			return nil, nil, err
		}
		vector, ok := x.Declaration("vector")
		if !ok || constructor != vector.Constructor {
			return nil, nil, ErrCodec
		}
		count, err := in.u32()
		if err != nil {
			return nil, nil, ErrCodec
		}
		if int64(count) > int64(in.limits.MaxVector) {
			return nil, nil, ErrLimit
		}
		result := make([]any, count)
		for index := range result {
			value, unknown, err := x.decodeType(in, item)
			if err != nil {
				return nil, nil, err
			}
			if unknown != nil {
				result[index] = *unknown
			} else {
				result[index] = value
			}
		}
		return result, nil, nil
	}
	constructor, err := in.u32()
	if err != nil {
		return nil, nil, err
	}
	declaration, ok := x.Constructor(constructor)
	if !ok {
		data := in.data[in.pos-4:]
		if in.borrowed {
			return nil, &Unknown{Constructor: constructor, Data: data, Borrowed: true}, nil
		}
		return nil, &Unknown{Constructor: constructor, Data: append([]byte(nil), data...)}, nil
	}
	value, err := x.decodeDeclared(in, declaration)
	if err != nil {
		return nil, nil, err
	}
	return value, nil, nil
}

type encoder struct {
	data []byte
}

func (x *encoder) u32(value uint32) {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	x.data = append(x.data, raw[:]...)
}

func (x *encoder) u64(value uint64) {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], value)
	x.data = append(x.data, raw[:]...)
}

func (x *encoder) bytes(value []byte) {
	if len(value) < 254 {
		x.data = append(x.data, byte(len(value)))
	} else {
		x.data = append(x.data, 254, byte(len(value)), byte(len(value)>>8), byte(len(value)>>16))
	}
	x.data = append(x.data, value...)
	for len(x.data)&3 != 0 {
		x.data = append(x.data, 0)
	}
}

type decoder struct {
	data     []byte
	pos      int
	depth    int
	limits   Limits
	borrowed bool
}

func (x *decoder) remaining() int {
	return len(x.data) - x.pos
}

func (x *decoder) u32() (uint32, error) {
	if x.remaining() < 4 {
		return 0, ErrCodec
	}
	value := binary.LittleEndian.Uint32(x.data[x.pos : x.pos+4])
	x.pos += 4
	return value, nil
}

func (x *decoder) u64() (uint64, error) {
	if x.remaining() < 8 {
		return 0, ErrCodec
	}
	value := binary.LittleEndian.Uint64(x.data[x.pos : x.pos+8])
	x.pos += 8
	return value, nil
}

func (x *decoder) bytes() ([]byte, error) {
	if x.remaining() < 1 {
		return nil, ErrCodec
	}
	first := int(x.data[x.pos])
	x.pos++
	length := first
	header := 1
	if first == 254 {
		if x.remaining() < 3 {
			return nil, ErrCodec
		}
		length = int(x.data[x.pos]) | int(x.data[x.pos+1])<<8 | int(x.data[x.pos+2])<<16
		x.pos += 3
		header = 4
	} else if first == 255 {
		return nil, ErrCodec
	}
	if length > x.limits.MaxBytes {
		return nil, ErrLimit
	}
	if x.remaining() < length {
		return nil, ErrCodec
	}
	value := x.data[x.pos : x.pos+length]
	x.pos += length
	padding := (4 - (length+header)&3) & 3
	if x.remaining() < padding {
		return nil, ErrCodec
	}
	for _, value := range x.data[x.pos : x.pos+padding] {
		if value != 0 {
			return nil, ErrCodec
		}
	}
	x.pos += padding
	return value, nil
}

func (x *decoder) fixed(length int) ([]byte, *Unknown, error) {
	if length < 0 || x.remaining() < length {
		return nil, nil, ErrCodec
	}
	value := x.data[x.pos : x.pos+length]
	x.pos += length
	if x.borrowed {
		return value, nil, nil
	}
	return append([]byte(nil), value...), nil, nil
}

func (x *decoder) enter() bool {
	if x.depth >= x.limits.MaxDepth {
		return false
	}
	x.depth++
	return true
}

func (x *decoder) leave() {
	x.depth--
}

func bareType(value string) string {
	if offset := strings.IndexByte(value, '?'); offset >= 0 {
		value = value[offset+1:]
	}
	value = strings.TrimPrefix(value, "!")
	value = strings.TrimPrefix(value, "%")
	return value
}

func optionalFlagName(value string) string {
	offset := strings.IndexByte(value, '.')
	if offset < 0 {
		return ""
	}
	return value[:offset]
}

func vectorElement(value string) (string, bool) {
	if strings.HasPrefix(value, "Vector<") && strings.HasSuffix(value, ">") {
		return value[7 : len(value)-1], true
	}
	if strings.HasPrefix(value, "vector<") && strings.HasSuffix(value, ">") {
		return value[7 : len(value)-1], true
	}
	return "", false
}

func encodeFixed(out *encoder, value any, length int) error {
	data, ok := value.([]byte)
	if !ok || len(data) != length {
		return ErrCodec
	}
	out.data = append(out.data, data...)
	return nil
}

func signed32(value any) (int32, bool) {
	switch value := value.(type) {
	case int32:
		return value, true
	case int:
		if int64(value) >= math.MinInt32 && int64(value) <= math.MaxInt32 {
			return int32(value), true
		}
	}
	return 0, false
}

func signed64(value any) (int64, bool) {
	switch value := value.(type) {
	case int64:
		return value, true
	case int:
		return int64(value), true
	}
	return 0, false
}

func unsigned(value any) (uint32, bool) {
	switch value := value.(type) {
	case uint32:
		return value, true
	case int32:
		return uint32(value), true
	case int:
		if value >= 0 {
			return uint32(value), true
		}
	}
	return 0, false
}

func boolean(value any) bool {
	item, ok := value.(bool)
	return ok && item
}
