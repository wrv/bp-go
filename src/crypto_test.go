package bp

import (
	"testing"
	"math/big"
)

func TestVectorPCommit(t *testing.T) {
	CP = NewECPrimeGroupKey(1)

	v := big.NewInt(3)
	p := CP.G[0].Mult(v)

}