// Package wire applies bounded, unambiguous JSON decoding around encoding/json.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var ErrInvalid = errors.New("invalid control message")

const MaxBody = 64 * 1024

// Decode rejects duplicate keys (including case-folded aliases understood by
// encoding/json), unknown fields, trailing values, excessive nesting and size.
// All JSON syntax and destination-type parsing remain in the standard library.
func Decode(data []byte, out any) error {
	if len(data) == 0 || len(data) > MaxBody {
		return ErrInvalid
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	count := 0
	var value func(int) error
	value = func(depth int) error {
		count++
		if depth > 24 || count > 2048 {
			return ErrInvalid
		}
		token, e := d.Token()
		if e != nil {
			return ErrInvalid
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := []string{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return ErrInvalid
				}
				name, ok := k.(string)
				if !ok || len(keys) >= 64 {
					return ErrInvalid
				}
				for _, old := range keys {
					if strings.EqualFold(old, name) {
						return ErrInvalid
					}
				}
				keys = append(keys, name)
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if value(0) != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
