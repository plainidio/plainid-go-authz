package plainidhttp

import (
	"bytes"
	"io"
	"net/http"
)

// bodyReader returns the request body, or nil when there is none to read.
func bodyReader(r *http.Request) io.Reader {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	return r.Body
}

// replaceBody puts the already-read bytes back on the request, so the backend
// still sees the body the PDP judged.
func replaceBody(r *http.Request, body []byte) {
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
}
