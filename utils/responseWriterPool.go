package utils

import (
	"net/http"
	"sync/atomic"

	pool "github.com/qydysky/part/pool"
)

type responseWriter struct {
	writen atomic.Bool
	Raw    http.ResponseWriter
}

func (t *responseWriter) Header() http.Header {
	return t.Raw.Header()
}

func (t *responseWriter) Write(b []byte) (int, error) {
	t.writen.Store(true)
	return t.Raw.Write(b)
}

func (t *responseWriter) WriteHeader(statusCode int) {
	if t.writen.CompareAndSwap(false, true) {
		t.Raw.WriteHeader(statusCode)
	}
}

var RWPool = pool.New(pool.PoolFunc[responseWriter]{
	New: func() *responseWriter {
		return new(responseWriter)
	},
	Reuse: func(w *responseWriter) *responseWriter {
		w.writen.Store(false)
		w.Raw = nil
		return w
	},
}, -1)
