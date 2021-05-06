package lpki

import (
	"math/big"
	"time"
)

func getSerial() *big.Int {
	// 同じ番号を過去に見たことがあると被りが検知されてブラウザに警告されるため、Nanosecond にしてある
	// ランダムでさらに保険をかけることもできるが、まあいったんはこれで
	return big.NewInt(int64(time.Now().Nanosecond()))
}
