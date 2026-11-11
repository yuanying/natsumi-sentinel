package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"sync"
	"unicode/utf8"
)

// BodyCapture keeps what the audit record needs of a request body while
// the body is sent on.
type BodyCapture struct {
	mu     sync.Mutex
	prefix []byte
	more   bool // the body is longer than prefix
	h      hash.Hash
	n      int64
	eof    bool
}

// CaptureBody reads the first limit bytes of r before anything is sent, so
// that they can be in the record written before the request goes out. It
// returns a reader that gives the whole body, prefix included, and measures
// it as it is read.
func CaptureBody(r io.Reader, limit int64) (*BodyCapture, io.Reader, error) {
	c := &BodyCapture{h: sha256.New()}
	// One byte past the limit tells a body exactly at the limit from a
	// longer one.
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(buf)) > limit {
		c.prefix, c.more = buf[:limit], true
	} else {
		c.prefix = buf
	}
	return c, &measured{c: c, r: io.MultiReader(bytes.NewReader(buf), r)}, nil
}

// Summary is what is known of the body so far: before the body is sent,
// the prefix (and, for a body within the limit, its size and hash); after
// it has been read to the end, the size and hash of the whole.
func (c *BodyCapture) Summary() Body {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := Body{Truncated: c.more}
	if looksBinary(c.prefix) {
		b.Binary = true
	} else {
		b.Text = string(trimPartialRune(c.prefix))
	}
	switch {
	case c.eof:
		b.Size = c.n
		b.SHA256 = hex.EncodeToString(c.h.Sum(nil))
	case !c.more:
		b.Size = int64(len(c.prefix))
		s := sha256.Sum256(c.prefix)
		b.SHA256 = hex.EncodeToString(s[:])
	default:
		b.Size = c.n
	}
	return b
}

type measured struct {
	c *BodyCapture
	r io.Reader
}

func (m *measured) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	m.c.mu.Lock()
	m.c.h.Write(p[:n])
	m.c.n += int64(n)
	if errors.Is(err, io.EOF) {
		m.c.eof = true
	}
	m.c.mu.Unlock()
	return n, err
}

// looksBinary reports whether b is not text: it holds a NUL, or is not
// UTF-8 apart from a character cut off at the end.
func looksBinary(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 {
		return true
	}
	return !utf8.Valid(trimPartialRune(b))
}

// trimPartialRune drops an incomplete UTF-8 sequence at the end of b, which
// the limit can leave when it cuts a character.
func trimPartialRune(b []byte) []byte {
	for i := 1; i < utf8.UTFMax && i <= len(b); i++ {
		c := b[len(b)-i]
		if utf8.RuneStart(c) {
			if !utf8.FullRune(b[len(b)-i:]) {
				return b[:len(b)-i]
			}
			break
		}
	}
	return b
}
