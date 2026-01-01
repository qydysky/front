package dealer

import "net/http"

type ResFunc struct {
	Dealer func(r *http.Response)
}
