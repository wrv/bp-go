package bp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestRPVerify1(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	// Testing smallest number in range
	if RPVerify(RPProve(big.NewInt(0))) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}
}

func TestRPVerify2(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	// Testing largest number in range
	if RPVerify(RPProve(new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(63), EC.N), big.NewInt(1)))) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}
}

func TestRPVerify3(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	// Testing the value 3
	if RPVerify(RPProve(big.NewInt(3))) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}
}

func TestRPVerify4(t *testing.T) {
	EC = NewECPrimeGroupKey(32)
	// Testing smallest number in range
	if RPVerify(RPProve(big.NewInt(0))) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}
}

func TestRPVerifyRand(t *testing.T) {
	EC = NewECPrimeGroupKey(64)

	ran, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), EC.N))
	check(err)

	// Testing the value 3
	if RPVerify(RPProve(ran)) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
		fmt.Printf("Random Value: %s", ran.String())
	}
}
