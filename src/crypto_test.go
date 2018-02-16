package bp

import (
	"testing"
	"math/big"
)

func TestVerifyParamGeneration(t *testing.T){
	CP2 := NewECPrimeGroupKey(2)

	if len(CP2.G) != len(CP2.H) {
		println("Failure - 2 param")
	} else {
		println("Success - 2 param")
	}

	CP3 := NewECPrimeGroupKey(3)

	if len(CP3.G) != len(CP3.H) {
		println("Failure - 3 param")
	} else {
		println("Success - 3 param")
	}
}

func TestVectorPCommit3(t *testing.T) {
	CP = NewECPrimeGroupKey(3)

	v := make([]*big.Int, 3)
	for j := range v {
		v[j] = big.NewInt(2)
	}

	output, r := VectorPCommit(v)

	if len(r) != 3 {
		println("Failure - rvalues doesn't match length of values")
	}
	// we will verify correctness by replicating locally and comparing output

	GVal := CP.G[0].Mult(v[0]).Add(CP.G[1].Mult(v[1]).Add(CP.G[2].Mult(v[2])))
	HVal := CP.H[0].Mult(r[0]).Add(CP.H[1].Mult(r[1]).Add(CP.H[2].Mult(r[2])))
	Comm := GVal.Add(HVal)

	if output.Equal(Comm) {
		println("Commitment correct")
	} else {
		println("Commitment failed")
	}
}

func TestInnerProductProve(t *testing.T) {

}


func TestInnerProduct(t *testing.T) {
	a := make([]*big.Int, 5)
	b := make([]*big.Int, 5)

	a[0] = big.NewInt(2)
	a[1] = big.NewInt(2)
	a[2] = big.NewInt(2)
	a[3] = big.NewInt(2)
	a[4] = big.NewInt(2)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(2)
	b[2] = big.NewInt(2)
	b[3] = big.NewInt(2)
	b[4] = big.NewInt(2)

	c := InnerProduct(a, b)

	if c.Cmp(big.NewInt(20)) == 0 {
		println("Success - Innerproduct works with 2")
	} else{
		println("Failure - Innerproduct equal to ")
		println(c.String())
	}

}