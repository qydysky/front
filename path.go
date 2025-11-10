package front

import (
	"iter"

	psync "github.com/qydysky/part/sync"
)

type Pather struct {
	Per    *Pather
	Next   *Pather
	Dealer *Route
	l      psync.RWMutex
}

func NewPather() *Pather {
	return &Pather{}
}

func (t *Pather) Add(r *Route) {
	ul := t.l.RLock()
	nextP := t.Next
	ul()

	if nextP == nil {
		ul := t.l.Lock()
		t.Next = &Pather{
			Per:    t,
			Dealer: r,
		}
		ul()
	} else {
		nextP.Add(r)
	}
}

func (t *Pather) Del(r *Route) {
	ul := t.l.RLock()
	isCur := t.Dealer == r
	nextP := t.Next
	perP := t.Per
	ul()

	if isCur {
		ul := perP.l.Lock()
		perP.Next = nextP
		ul()
		if nextP != nil {
			ul := nextP.l.Lock()
			nextP.Per = perP
			ul()
		}
	} else if nextP != nil {
		nextP.Del(r)
	}
}

func (t *Pather) Size() (i uint32) {
	tmp := t
	for {
		ul := tmp.l.RLock()
		nextP := tmp.Next
		ul()
		if nextP != nil {
			i++
			tmp = nextP
		} else {
			return
		}
	}
}

func (t *Pather) Range() iter.Seq[*Route] {
	return func(yield func(*Route) bool) {
		tmp := t
		for {
			ul := tmp.l.RLock()
			route := tmp.Dealer
			tmp = tmp.Next
			ul()
			if route != nil && !yield(route) {
				return
			} else if tmp == nil {
				return
			}
		}
	}
}
