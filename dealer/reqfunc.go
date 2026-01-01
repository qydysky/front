package dealer

import "net/http"

type ReqFunc struct {
	Dealer func(r *http.Request)
}
