package filiter

import "net/http"

type ResFunc func(req *http.Request, res *http.Response) (pass bool)
