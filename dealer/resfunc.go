package dealer

import "net/http"

type ResFunc struct {
	Dealer func(req *http.Request, res *http.Response)
}
