package util

import (
	"crypto/rand"
	"encoding/hex"
	"math"
)

func GenRandomStr(length int) string {
	buff := make([]byte, int(math.Round(float64(length)/2)))
	rand.Read(buff)
	str := hex.EncodeToString(buff)
	return str[:length]
}
