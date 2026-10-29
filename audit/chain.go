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
// cut from the end, or a chain stripped of every prev_hash, leave a log
// that verifies: VerifyAnchored checks it against an anchor kept
// elsewhere. It returns a *ChainError for a break.
func Verify(r io.Reader) (Summary, error) {
	s, _, err := verify(r, 0)
	return s, err
}

// Anchor is a chained line of a log, kept apart from it (by the hub):
// the 1-based Line and its LineHash. Summary.Anchor makes one.
type Anchor struct {
	Line int
	Hash string
}

// Anchor is the anchor of the log as read: its last line, when chained.
func (s Summary) Anchor() Anchor {
	if s.Last == "" {
		return Anchor{}
	}
	return Anchor{Line: s.Records, Hash: s.Last}
}

// VerifyAnchored is Verify for a log anchored at a: the log reaches line
// a.Line, that line is chained and hashes to a.Hash. A log cut before the
// anchor, or whose chain was stripped (lines without prev_hash up to the
// anchor: a log that Verify alone reads as legacy) is a *ChainError.
func VerifyAnchored(r io.Reader, a Anchor) (Summary, error) {
	if a.Line < 1 || a.Hash == "" {
		return Summary{}, errors.New("audit: empty anchor")
	}
	s, at, err := verify(r, a.Line)
	switch {
	case err != nil:
		return s, err
	case s.Records < a.Line:
		return s, &ChainError{s.Records + 1, fmt.Sprintf("the log ends before its anchor at line %d", a.Line)}
	case s.Legacy >= a.Line:
		return s, &ChainError{a.Line, "the anchored line has no prev_hash: the chain was stripped"}
	case LineHash(at) != a.Hash:
		return s, &ChainError{a.Line, "the anchored line does not match its anchor"}
	}
	return s, nil
}

// verify is Verify, also returning line number at (0: none).
func verify(r io.Reader, at int) (Summary, []byte, error) {
	var s Summary
	var atLine []byte
	br := bufio.NewReader(r)
	var prev []byte
	chained := false
	for n := 1; ; n++ {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && err == io.EOF {
			return s, atLine, nil
		}
		if err != nil && err != io.EOF {
			return s, nil, fmt.Errorf("audit: %w", err)
		}
		if err == io.EOF {
			return s, nil, &ChainError{n, "the last line has no newline (a write cut short)"}
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		var head struct {
			PrevHash *string `json:"prev_hash"`
		}
		if err := json.Unmarshal(line, &head); err != nil || len(line) == 0 || line[0] != '{' {
			return s, nil, &ChainError{n, "not a JSON object"}
		}
		s.Records++
		switch {
		case head.PrevHash == nil && !chained:
			s.Legacy++
		case head.PrevHash == nil:
			return s, nil, &ChainError{n, "a record without prev_hash after the chain started"}
		default:
			want := Genesis
			if prev != nil {
				want = LineHash(prev)
			}
			if *head.PrevHash != want {
				return s, nil, &ChainError{n, "prev_hash does not match the line before it"}
			}
			chained = true
			s.Last = LineHash(line)
		}
		prev = bytes.Clone(line)
		if n == at {
			atLine = prev
		}
	}
}

// errNoEvent is returned for a record without an event.
var errNoEvent = errors.New("audit: record without an event")
