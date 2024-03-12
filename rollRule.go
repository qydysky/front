package front

import (
	"math/rand/v2"
	"slices"
)

var rollRuleMap = make(map[string]func(backLink []*Back))

func init() {
	rollRuleMap[`disable_MinFirst`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return a.disableC/(a.Weight+1) - b.disableC/(b.Weight+1)
		})
	}

	rollRuleMap[`dealingC_MinFirst`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return a.dealingC/(a.Weight+1) - b.dealingC/(b.Weight+1)
		})
	}

	rollRuleMap[`chosenC_MinFirst`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return a.chosenC/(a.Weight+1) - b.chosenC/(b.Weight+1)
		})
	}

	rollRuleMap[`lastResDur_MinFirst`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return int(a.lastResDru.Milliseconds()/int64(a.Weight+1) - b.lastResDru.Milliseconds()/int64(b.Weight+1))
		})
	}

	rollRuleMap[`resDur_MinFirst`] = func(backLink []*Back) {
		slices.SortStableFunc(backLink, func(a, b *Back) int {
			return int(a.resDru.Milliseconds()/int64(a.Weight+1) - b.resDru.Milliseconds()/int64(b.Weight+1))
		})
	}
}

func rand_Shuffle(backLink []*Back) {
	rand.Shuffle(len(backLink), func(i, j int) {
		backLink[i], backLink[j] = backLink[j], backLink[i]
	})
}
