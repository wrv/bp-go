package bp

import (
	"fmt"
	"math/big"
	"testing"
)

func TestMultiRPVerify1(t *testing.T) {
	values := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	EC = NewECPrimeGroupKey(64 * len(values))
	// Testing smallest number in range
	proof := MRPProve(values)
	proofString := fmt.Sprintf("%s", proof)

	fmt.Println(len(proofString)) // length is good measure of bytes, correct?

	if MRPVerify(proof) {
		fmt.Println("Multi Range Proof Verification works")
	} else {
		t.Error("***** Multi Range Proof FAILURE")
	}
}

func TestMultiRPVerify2(t *testing.T) {
	values := []*big.Int{big.NewInt(0)}
	EC = NewECPrimeGroupKey(64 * len(values))
	// Testing smallest number in range
	if MRPVerify(MRPProve(values)) {
		fmt.Println("Multi Range Proof Verification works")
	} else {
		t.Error("***** Multi Range Proof FAILURE")
	}
}

func TestMultiRPVerify3(t *testing.T) {
	values := []*big.Int{big.NewInt(0), big.NewInt(1)}
	EC = NewECPrimeGroupKey(64 * len(values))
	// Testing smallest number in range
	if MRPVerify(MRPProve(values)) {
		fmt.Println("Multi Range Proof Verification works")
	} else {
		t.Error("***** Multi Range Proof FAILURE")
	}
}

func TestMultiRPVerify4(t *testing.T) {
	for j := 1; j < 33; j = 2 * j {
		values := make([]*big.Int, j)
		for k := 0; k < j; k++ {
			values[k] = big.NewInt(0)
		}

		EC = NewECPrimeGroupKey(64 * len(values))
		// Testing smallest number in range
		proof := MRPProve(values)
		proofString := fmt.Sprintf("%s", proof)

		fmt.Println(len(proofString)) // length is good measure of bytes, correct?

		if MRPVerify(proof) {
			fmt.Println("Multi Range Proof Verification works")
		} else {
			t.Error("***** Multi Range Proof FAILURE")
		}
	}
}
