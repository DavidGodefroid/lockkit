package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// ErrOutputCap means a value encodes to more than Caps.MaxOutputBytes:
// nothing is written. The product pages or narrows its result.
var ErrOutputCap = errors.New("render: the result is over the output cap")

// Value writes v as one line of JSON: every string, object keys included,
// escaped and cut at Caps.MaxCellChars characters (as a table cell in JSON
// mode); numbers, booleans and nulls keep their JSON type. The output is
// at most Caps.MaxOutputBytes, or ErrOutputCap and nothing written.
// MaxRows does not apply: a product bounds its own lists.
func Value(w io.Writer, v any, l Caps) error {
	l = effective(l)
	raw, err := encode(v)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return fmt.Errorf("render: %w", err)
	}
	out, err := encode(capTree(tree, l.MaxCellChars))
	if err != nil {
		return err
	}
	if len(out) > l.MaxOutputBytes {
		return ErrOutputCap
	}
	_, err = w.Write(out)
	return err
}

func capTree(v any, maxChars int) any {
	switch x := v.(type) {
	case string:
		s, _ := capTextCut(x, maxChars, true)
		return s
	case []any:
		for i := range x {
			x[i] = capTree(x[i], maxChars)
		}
		return x
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(x))
		for _, k := range keys {
			ck, _ := capTextCut(k, maxChars, true)
			out[ck] = capTree(x[k], maxChars)
		}
		return out
	}
	return v // json.Number, bool, nil
}
