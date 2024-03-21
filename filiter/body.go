package filiter

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/dustin/go-humanize"
	pio "github.com/qydysky/part/io"
)

type Body struct {
	Action   string `json:"action"`
	ReqSize  string `json:"reqSize"`
	MatchExp string `json:"matchExp"`
}

func (t *Body) Valid() bool {
	return t.MatchExp != ""
}

func (t *Body) Match(r *http.Request) (ok bool, err error) {
	if !t.Valid() {
		return true, nil
	}
	if exp, e := regexp.Compile(t.MatchExp); e == nil {
		if t.ReqSize == "" {
			t.ReqSize = "1M"
		}

		var (
			size, err = humanize.ParseBytes(t.ReqSize)
			buf       = make([]byte, size)
			n         int
		)

		if err != nil {
			return false, err
		}

		for n < int(size) && err == nil {
			var nn int
			nn, err = r.Body.Read(buf[n:])
			n += nn
		}

		if n >= int(size) {
			r.Body = pio.RWC{
				R: io.MultiReader(bytes.NewReader(buf), r.Body).Read,
				C: r.Body.Close,
			}
			return false, errors.New("body overflow")
		} else if err != nil && !errors.Is(err, io.EOF) {
			r.Body.Close()
			return false, err
		}
		buf = buf[:n]

		switch t.Action {
		case "access":
			if !exp.Match(buf) {
				r.Body.Close()
				return false, nil
			}
		case "deny":
			if exp.Match(buf) {
				r.Body.Close()
				return false, nil
			}
		}

		r.Body = pio.RWC{
			R: bytes.NewReader(buf).Read,
			C: r.Body.Close,
		}

		return true, nil
	} else {
		return false, e
	}
}
