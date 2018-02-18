package bp

import (
	"testing"
	"math/big"
)

func TestInnerProductProveLen2(t *testing.T) {
	println("TestInnerProductProve")
	CP = NewECPrimeGroupKey(2)
	a := make([]*big.Int, 2)
	b := make([]*big.Int, 2)

	a[0] = big.NewInt(2)
	a[1] = big.NewInt(2)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(2)

	c := big.NewInt(8)

	P := TwoVectorPCommit(a, b)

	ipp := InnerProductProve(a, b, c, P)

	if InnerProductVerify(c, P, ipp){
		println("Inner Product Proof correct")
	} else {
		println("Inner Product Proof incorrect")
	}
}


func TestInnerProductProveLen4(t *testing.T) {
	println("TestInnerProductProve")
	CP = NewECPrimeGroupKey(4)
	a := make([]*big.Int, 4)
	b := make([]*big.Int, 4)

	a[0] = big.NewInt(2)
	a[1] = big.NewInt(2)
	a[2] = big.NewInt(2)
	a[3] = big.NewInt(2)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(2)
	b[2] = big.NewInt(2)
	b[3] = big.NewInt(2)

	c := big.NewInt(16)

	P := TwoVectorPCommit(a, b)

	ipp := InnerProductProve(a, b, c, P)

	if InnerProductVerify(c, P, ipp){
		println("Inner Product Proof correct")
	} else {
		println("Inner Product Proof incorrect")
	}
}


func TestVectorPCommit3(t *testing.T) {
	println("TestVectorPCommit3")
	CP := NewECPrimeGroupKey(3)

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

func TestInnerProduct(t *testing.T) {
	println("TestInnerProduct")
	a := make([]*big.Int, 4)
	b := make([]*big.Int, 4)

	a[0] = big.NewInt(2)
	a[1] = big.NewInt(2)
	a[2] = big.NewInt(2)
	a[3] = big.NewInt(2)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(2)
	b[2] = big.NewInt(2)
	b[3] = big.NewInt(2)

	c := InnerProduct(a, b)

	if c.Cmp(big.NewInt(16)) == 0 {
		println("Success - Innerproduct works with 2")
	} else{
		println("Failure - Innerproduct equal to ")
		println(c.String())
	}

}


