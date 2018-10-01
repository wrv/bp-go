package bp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestValueBreakdown(t *testing.T) {
	v := big.NewInt(20)
	yes := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", 64)))
	vec2 := PowerVector(64, big.NewInt(2))

	calc := InnerProduct(yes, vec2)

	if v.Cmp(calc) != 0 {
		t.Error("Binary Value Breakdown - Failure :(")
		fmt.Println(yes)
		fmt.Println(vec2)
		fmt.Println(calc)
	} else {
		fmt.Println("Binary Value Breakdown - Success!")
		//fmt.Println(yes)
		//fmt.Println(vec2)
		//fmt.Println(calc)
	}
}

func TestValueBreakdownRand(t *testing.T) {
	v, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), EC.N))
	check(err)

	yes := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", 64)))
	vec2 := PowerVector(64, big.NewInt(2))

	calc := InnerProduct(yes, vec2)

	if v.Cmp(calc) != 0 {
		t.Error("Binary Value Breakdown - Failure :(")
		fmt.Println(yes)
		fmt.Println(vec2)
		fmt.Println(calc)
	} else {
		fmt.Println("Binary Value Breakdown - Success!")
	}

}

func TestVectorHadamard(t *testing.T) {
	a := make([]*big.Int, 5)
	a[0] = big.NewInt(1)
	a[1] = big.NewInt(1)
	a[2] = big.NewInt(1)
	a[3] = big.NewInt(1)
	a[4] = big.NewInt(1)

	c := VectorHadamard(a, a)

	success := true

	for i := range c {
		if c[i].Cmp(a[i]) != 0 {
			success = false
		}
	}
	if !success {
		t.Error("Failure in the Hadamard")
	} else {
		fmt.Println("Hadamard good")
	}
}

func TestInnerProduct(t *testing.T) {
	fmt.Println("TestInnerProduct")
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
		fmt.Println("Success - Innerproduct works with 2")
	} else {
		t.Error("Failure - Innerproduct equal to ")
		fmt.Println(c.String())
	}

}
