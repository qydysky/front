package front

import (
	"iter"
	"sync"
)

type Pather struct {
	Next   *Pather
	Dealer *Route
	l      sync.RWMutex
}

func (t *Pather) Add(r *Route) {
	t.l.Lock()
	defer t.l.Unlock()

	if t.Dealer == nil {
		t.Dealer = r
	} else if t.Next == nil {
		t.Next = &Pather{
			Dealer: r,
		}
	} else {
		t.Next.Add(r)
	}
}

func (t *Pather) Del(r *Route) {
	t.l.Lock()
	defer t.l.Unlock()

	if t.Dealer == r {
		t.Dealer = nil
	} else if t.Next == nil {
		t.Next = &Pather{
			Dealer: r,
		}
	} else {
		t.Next.Add(r)
	}
}

// return true if not matched
func (t *Pather) Range() iter.Seq[*Route] {
	return func(yield func(*Route) bool) {
		tmp := t
		for {
			tmp.l.RLock()
			if yield(tmp.Dealer) && tmp.Next != nil {
				tmp = tmp.Next
			}
			tmp.l.RUnlock()
		}
	}
}
