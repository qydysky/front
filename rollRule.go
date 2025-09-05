package front

import (
	"math/rand/v2"
	"slices"
	"time"
)

var rollRuleMap = make(map[string]func(backLink []*Back))

func init() {
	rollRuleMap[`order`] = func(backLink []*Back) {}

	rollRuleMap[`disable_MinFirst`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return int(a.DisableC/(a.Weight+1) - b.DisableC/(b.Weight+1))
		})
	}

	rollRuleMap[`dealingC_MinFirst`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return int(a.DealingC/(a.Weight+1) - b.DealingC/(b.Weight+1))
		})
	}

	rollRuleMap[`chosenC_MinFirst`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return int(a.ChosenC/(a.Weight+1) - b.ChosenC/(b.Weight+1))
		})
	}

	rollRuleMap[`loop`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return int(time.Since(b.LastChosenT[0]).Milliseconds()*int64(b.Weight+1) - time.Since(a.LastChosenT[0]).Milliseconds()*int64(a.Weight+1))
		})
	}
}

func rand_Shuffle(backLink []*Back) {
	rand.Shuffle(len(backLink), func(i, j int) {
		backLink[i], backLink[j] = backLink[j], backLink[i]
	})
}
