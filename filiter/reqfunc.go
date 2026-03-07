package filiter

import "net/http"

type ReqFunc func(r *http.Request) (pass bool)
