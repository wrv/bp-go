package bp


import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var CP CryptoParams
var VecLength = 1
/*
Implementation of BulletProofs

*/

type ECPoint struct {
	X, Y *big.Int
}

func ECZero() ECPoint{
	return ECPoint{big.NewInt(0), big.NewInt(0)}
}

// Equal returns true if points p (self) and p2 (arg) are the same.
func (p ECPoint) Equal(p2 ECPoint) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

// Mult multiplies point p by scalar s and returns the resulting point
func (p ECPoint) Mult(s *big.Int) ECPoint {
	modS := new(big.Int).Mod(s, CP.N)
	X, Y := CP.C.ScalarMult(p.X, p.Y, modS.Bytes())
	return ECPoint{X, Y}
}

// Add adds points p and p2 and returns the resulting point
func (p ECPoint) Add(p2 ECPoint) ECPoint {
	X, Y := CP.C.Add(p.X, p.Y, p2.X, p2.Y)
	return ECPoint{X, Y}
}

// Neg returns the additive inverse of point p
func (p ECPoint) Neg() ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := negY.Mod(negY, CP.C.Params().P)
	return ECPoint{p.X, modValue}
}

type CryptoParams struct{
	C elliptic.Curve		// curve
	KC *btcec.KoblitzCurve	// curve
	G []ECPoint				// slice of gen 1
	H []ECPoint				// slice of gen 2
	N *big.Int				// scalar prime
	V int				// Vector length
}

func (c CryptoParams) Zero() ECPoint {
	return ECPoint{big.NewInt(0), big.NewInt(0)}
}


func check(e error) {
	if e != nil {
		panic(e)
	}
}

/*
Vector Pedersen Commitment

Given some array of values, we commit the array with different generators
for each element and for each randomness.
 */
func VectorPCommit(value []*big.Int) (ECPoint, []*big.Int) {
	R := make([]*big.Int, CP.V)

	commitment := CP.Zero()

	for i := 0; i < CP.V; i++{
		r, err := rand.Int(rand.Reader, CP.N)
		check(err)

		R[i] = r

		modValue := new(big.Int).Mod(value[i], CP.N)

		// mG, rH
		lhsX, lhsY := CP.C.ScalarMult(CP.G[i].X, CP.G[i].Y, modValue.Bytes())
		rhsX, rhsY := CP.C.ScalarMult(CP.H[i].X, CP.H[i].Y, r.Bytes())

		commitment = commitment.Add(ECPoint{lhsX, lhsY}).Add(ECPoint{rhsX, rhsY})
	}

	return commitment, R
}




type BulletProof struct {
	L 	ECPoint
	R 	ECPoint
	a	*big.Int
	b 	*big.Int
}

func InnerProduct(a []*big.Int, b []*big.Int) *big.Int {

	c := big.NewInt(0)

	for i := range a{
		c = new(big.Int).Add(c, new(big.Int).Mul(a[i], b[i]))
	}

	return new(big.Int).Mod(c, CP.C.Params().P)
}


/* Inner Product Argument

Proves that <a,b>=c

This is a building block for BulletProofs

*/
func InnerProductProveSub(a []*big.Int, b []*big.Int, c *big.Int, u ECPoint, P ECPoint) BulletProof {
	if len(a) == len(b) && len(a) ==1{
		// Prover sends a & b
		return BulletProof{ECPoint{big.NewInt(0),big.NewInt(0)}, ECPoint{big.NewInt(0),big.NewInt(0)}, a[0], b[0]}
	}

	nprime := len(a)/2

	cl := InnerProduct(a[:nprime], b[nprime:])
	cr := InnerProduct(a[nprime:], b[:nprime])



	return BulletProof{ECZero(), ECZero(), cl, cr}
}

func InnerProductProve(a []*big.Int, b []*big.Int, c *big.Int, u, P ECPoint) BulletProof{
	// randomly generate an x value from public data
	x := sha256.Sum256(a[0].Bytes()) // TODO: FIXME

	Pprime := P.Add(u.Mult(new(big.Int).Mul(new(big.Int).SetBytes(x[:]), c)))

	return InnerProductProveSub(a, b, c, u, Pprime)
}

// NewECPrimeGroupKey returns the curve (field),
// Generator 1 x&y, Generator 2 x&y, order of the generators
func NewECPrimeGroupKey(n int) CryptoParams {
	curValue := btcec.S256().Gx
	s256 := sha256.New()
	gen1Vals := make([]ECPoint, n)
	gen2Vals := make([]ECPoint, n)

	i := 0;
	confirmed := 0;
	for confirmed < 2*n {
		s256.Write(new(big.Int).Add(curValue, big.NewInt(int64(i))).Bytes())

		potentialXValue := make([]byte, 33)
		binary.LittleEndian.PutUint32(potentialXValue, 2)
		for i, elem := range s256.Sum(nil) {
			potentialXValue[i+1] = elem
		}

		gen2, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
		if err == nil{
			if confirmed % 2 == 0{
				gen1Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
			} else {
				gen2Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
			}
			confirmed += 1;
		}
		i += 1;
	}

	return CryptoParams{
		btcec.S256(),
		btcec.S256(),
		gen1Vals,
		gen2Vals,
		btcec.S256().N,
		n}
}



func init() {
	CP = NewECPrimeGroupKey(VecLength)
	fmt.Println(CP)
}