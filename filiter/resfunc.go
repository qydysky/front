package filiter

import "net/http"

type ResFunc struct {
	Filiter func(req *http.Request, res *http.Response) (pass bool)
}
