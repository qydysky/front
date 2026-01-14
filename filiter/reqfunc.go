package filiter

import "net/http"

type ReqFunc struct {
	Filiter func(r *http.Request) (pass bool)
}
