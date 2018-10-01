package bp

import (
	"fmt"
	"math/big"
	"testing"
)

func TestVectorPCommit3(t *testing.T) {
	fmt.Println("TestVectorPCommit3")
	EC = NewECPrimeGroupKey(3)

	v := make([]*big.Int, 3)
	for j := range v {
		v[j] = big.NewInt(2)
	}

	output, r := VectorPCommit(v)

	if len(r) != 3 {
		fmt.Println("Failure - rvalues doesn't match length of values")
	}
	// we will verify correctness by replicating locally and comparing output

	GVal := EC.BPG[0].Mult(v[0]).Add(EC.BPG[1].Mult(v[1]).Add(EC.BPG[2].Mult(v[2])))
	HVal := EC.BPH[0].Mult(r[0]).Add(EC.BPH[1].Mult(r[1]).Add(EC.BPH[2].Mult(r[2])))
	Comm := GVal.Add(HVal)

	if output.Equal(Comm) {
		fmt.Println("Commitment correct")
	} else {
		t.Error("Commitment failed")
	}
}
