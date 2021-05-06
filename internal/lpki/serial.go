package lpki

import (
	"math/big"
	"sync"
)

// 1 ~ 1000 は CA のために予約しておく
var sn = big.NewInt(1000)
var snM sync.Mutex

func incrementSerial() *big.Int {
	snM.Lock()
	defer snM.Unlock()
	sn.Add(sn, big.NewInt(1))
	rv := big.NewInt(0)
	return rv.Add(rv, sn)
}
