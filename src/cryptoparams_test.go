package bp

import (
	"fmt"
	"math/big"
	"testing"
)

func BenchmarkMRPVerifySize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for j := 1; j < 257; j *= 2 {
			values := make([]*big.Int, j)
			for k := 0; k < j; k++ {
				values[k] = big.NewInt(0)
			}

			EC = NewECPrimeGroupKey(64 * len(values))
			// Testing smallest number in range
			proof := MRPProve(values)
			proofString := fmt.Sprintf("%s", proof)
			//fmt.Println(proofString)
			fmt.Printf("Size for %d values: %d bytes\n", j, len(proofString)) // length is good measure of bytes, correct?

			if MRPVerify(proof) {
				fmt.Println("Multi Range Proof Verification works")
			} else {
				fmt.Println("***** Multi Range Proof FAILURE")
			}
		}
	}
}

var result MultiRangeProof
var boores bool

func BenchmarkMRPProve16(b *testing.B) {
	j := 16
	values := make([]*big.Int, j)
	for k := 0; k < j; k++ {
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	var r MultiRangeProof
	for i := 0; i < b.N; i++ {
		r = MRPProve(values)
	}

	result = r
}

func BenchmarkMRPVerify16(b *testing.B) {
	j := 16
	values := make([]*big.Int, j)
	for k := 0; k < j; k++ {
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	proof := MRPProve(values)

	var r bool
	for i := 0; i < b.N; i++ {
		r = MRPVerify(proof)
	}
	boores = r
}

func BenchmarkMRPProve32(b *testing.B) {
	j := 32
	values := make([]*big.Int, j)
	for k := 0; k < j; k++ {
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	var r MultiRangeProof
	for i := 0; i < b.N; i++ {
		r = MRPProve(values)
	}
	result = r
}

func BenchmarkMRPVerify32(b *testing.B) {
	j := 32
	values := make([]*big.Int, j)
	for k := 0; k < j; k++ {
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	proof := MRPProve(values)
	var r bool
	for i := 0; i < b.N; i++ {
		r = MRPVerify(proof)
	}
	boores = r
}
