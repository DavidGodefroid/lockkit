package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Genesis is the prev_hash of the first record of an empty log.
const Genesis = "genesis"

// LineHash is the prev_hash of the record that follows line: "sha256:" and
// the hex SHA-256 of the line's bytes, without its newline.
func LineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// lastLine returns the last line of f (nil when f is empty) and whether it
// lacks its newline (a write cut short). It reads back from the end.
func lastLine(f *os.File) (line []byte, cut bool, err error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	size := fi.Size()
	if size == 0 {
		return nil, false, nil
	}
	const chunk = 64 << 10
	var tail []byte
	end := size
	for end > 0 {
		n := int64(chunk)
		if n > end {
			n = end
		}
		b := make([]byte, n)
		if _, err := f.ReadAt(b, end-n); err != nil {
			return nil, false, err
		}
		tail = append(b, tail...)
		end -= n
		// The last line starts after the last newline but the final byte.
		if i := bytes.LastIndexByte(tail[:len(tail)-1], '\n'); i >= 0 || end == 0 {
			if size > 0 && tail[len(tail)-1] != '\n' {
				cut = true
			}
			line = bytes.TrimSuffix(tail[i+1:], []byte("\n"))
			return line, cut, nil
		}
	}
	return nil, false, nil
}

// Summary is what Verify read.
type Summary struct {
	// Records is the number of lines, Legacy those written before the
	// chain (without prev_hash), at the start of the log.
	Records, Legacy int
	// Last is the LineHash of the last chained line, "" when none: an
	// anchor kept elsewhere (the hub's own log) detects a cut tail.
	Last string
}

// ChainError is a break of the chain, at a 1-based line of the log.
type ChainError struct {
	Line   int
	Reason string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("audit: line %d: %s", e.Line, e.Reason)
}

// Verify reads an audit log and checks its chain: every line is a JSON
// object; lines without prev_hash may only precede the first chained one
// (the format before the chain); from there, each prev_hash is the
// LineHash of the line before it, and Genesis only on the first line. A
// record edited, removed, inserted or reordered breaks the chain. Records
// cut from the end leave a valid chain: compare Summary.Last with an anchor
// kept elsewhere. It returns a *ChainError for a break.
func Verify(r io.Reader) (Summary, error) {
	var s Summary
	br := bufio.NewReader(r)
	var prev []byte
	chained := false
	for n := 1; ; n++ {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && err == io.EOF {
			return s, nil
		}
		if err != nil && err != io.EOF {
			return s, fmt.Errorf("audit: %w", err)
		}
		if err == io.EOF {
			return s, &ChainError{n, "the last line has no newline (a write cut short)"}
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		var head struct {
			PrevHash *string `json:"prev_hash"`
		}
		if err := json.Unmarshal(line, &head); err != nil || len(line) == 0 || line[0] != '{' {
			return s, &ChainError{n, "not a JSON object"}
		}
		s.Records++
		switch {
		case head.PrevHash == nil && !chained:
			s.Legacy++
		case head.PrevHash == nil:
			return s, &ChainError{n, "a record without prev_hash after the chain started"}
		default:
			want := Genesis
			if prev != nil {
				want = LineHash(prev)
			}
			if *head.PrevHash != want {
				return s, &ChainError{n, "prev_hash does not match the line before it"}
			}
			chained = true
			s.Last = LineHash(line)
		}
		prev = bytes.Clone(line)
	}
}

// errNoEvent is returned for a record without an event.
var errNoEvent = errors.New("audit: record without an event")
