package bp


import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"math"
	"strconv"
	"fmt"
)

var CP CryptoParams
var VecLength = 2
/*
Implementation of BulletProofs

*/

type ECPoint struct {
	X, Y *big.Int
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
	U ECPoint				// a point that is a fixed group element with an unknown discrete-log relative to g,h
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

Given an array of values, we commit the array with different generators
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

/*
Two Vector P Commit

Given an array of values, we commit the array with different generators
for each element and for each randomness.
 */
func TwoVectorPCommit(a []*big.Int, b []*big.Int) (ECPoint) {
	commitment := CP.Zero()

	for i := 0; i < CP.V; i++{
		modA := new(big.Int).Mod(a[i], CP.N)
		modB := new(big.Int).Mod(b[i], CP.N)

		// aG, bH
		lhsX, lhsY := CP.C.ScalarMult(CP.G[i].X, CP.G[i].Y, modA.Bytes())
		rhsX, rhsY := CP.C.ScalarMult(CP.H[i].X, CP.H[i].Y, modB.Bytes())

		commitment = commitment.Add(ECPoint{lhsX, lhsY}).Add(ECPoint{rhsX, rhsY})
	}

	return commitment
}


/*
Vector Pedersen Commitment with Gens

Given an array of values, we commit the array with different generators
for each element and for each randomness.

We also pass in the Generators we want to use
 */
func TwoVectorPCommitWithGens(G,H []ECPoint, a, b []*big.Int) (ECPoint) {
	commitment := CP.Zero()

	for i := 0; i < len(G); i++{
		modA := new(big.Int).Mod(a[i], CP.N)
		modB := new(big.Int).Mod(b[i], CP.N)

		// mG, rH
		lhsX, lhsY := CP.C.ScalarMult(G[i].X, G[i].Y, modA.Bytes())
		rhsX, rhsY := CP.C.ScalarMult(H[i].X, H[i].Y, modB.Bytes())

		commitment = commitment.Add(ECPoint{lhsX, lhsY}).Add(ECPoint{rhsX, rhsY})
	}

	return commitment
}


// The length here always has to be a power of two
func InnerProduct(a []*big.Int, b []*big.Int) *big.Int {

	c := big.NewInt(0)

	for i := range a{
		c = new(big.Int).Add(c, new(big.Int).Mul(a[i], b[i]))
	}

	return new(big.Int).Mod(c, CP.C.Params().P)
}

func VectorAdd(v []*big.Int, w []*big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v{
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], w[i]), CP.N)
	}

	return result
}

func ScalarVectorMul(v []*big.Int, s *big.Int) []*big.Int {

	result := make([]*big.Int, len(v))

	for i := range v{
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], s), CP.N)
	}

	return result
}


/*
InnerProd Proof

This stores the argument values

 */
type InnerProdArg struct {
	L 	[]ECPoint
	R 	[]ECPoint
	x 	[]*big.Int
	a	*big.Int
	b 	*big.Int
}



func GenerateNewParams(G, H []ECPoint, x *big.Int, L, R, P ECPoint) ([]ECPoint, []ECPoint, ECPoint){
	nprime := len(G)/2

	Gprime := make([]ECPoint, nprime)
	Hprime := make([]ECPoint, nprime)

	xinv := new(big.Int).ModInverse(x, CP.N)

	// Gprime = xinv * G[:nprime] + x*G[nprime:]
	// Hprime = x * H[:nprime] + xinv*H[nprime:]

	for i := range Gprime {
		Gprime[i] = G[i].Mult(xinv).Add(G[i+nprime].Mult(x))
		Hprime[i] = H[i].Mult(x).Add(H[i+nprime].Mult(xinv))
	}

	Pprime := L.Mult(new(big.Int).Mul(x, x)).Add(P).Add(R.Mult(new(big.Int).Mul(xinv, xinv))) // x^2 * L + P + xinv^2 * R

	return Gprime, Hprime, Pprime
}

/* Inner Product Argument

Proves that <a,b>=c

This is a building block for BulletProofs

*/
func InnerProductProveSub(proof InnerProdArg, G, H []ECPoint, a []*big.Int, b []*big.Int, u ECPoint, P ECPoint) InnerProdArg {
	if len(a) == 1{
		// Prover sends a & b
		proof.a = a[0]
		proof.b = b[0]
		return proof
	}

	curIt := int(math.Log2(float64(len(a))))-1

	nprime := len(a)/2
	//println(nprime)
	//println(len(H))
	cl := InnerProduct(a[:nprime], b[nprime:])
	cr := InnerProduct(a[nprime:], b[:nprime])
	L := TwoVectorPCommitWithGens(G[nprime:], H[:nprime], a[:nprime], b[nprime:]).Add(u.Mult(cl))
	R := TwoVectorPCommitWithGens(G[:nprime], H[nprime:], a[nprime:], b[:nprime]).Add(u.Mult(cr))

	proof.L[curIt] = L
	proof.R[curIt] = R

	// prover sends L & R and gets a challenge
	s256 := sha256.Sum256([]byte(
				L.X.String() + L.Y.String() +
				R.X.String() + R.Y.String()))

	x := new(big.Int).SetBytes(s256[:])

	proof.x[curIt] = x

	Gprime, Hprime, Pprime := GenerateNewParams(G, H, x, L, R, P)
	//fmt.Printf("Prover - Intermediate Pprime value: %s \n", Pprime)
	xinv := new(big.Int).ModInverse(x, CP.N)
	aprime := VectorAdd(ScalarVectorMul(a[:nprime], x), ScalarVectorMul(a[nprime:], xinv))
	bprime := VectorAdd(ScalarVectorMul(b[:nprime], xinv), ScalarVectorMul(b[nprime:], x))

	return InnerProductProveSub(proof, Gprime, Hprime, aprime, bprime, u, Pprime)
}

func InnerProductProve(a []*big.Int, b []*big.Int, c *big.Int, P ECPoint) InnerProdArg {
	loglen := int(math.Log2(float64(len(a))))

	challenges := make([]*big.Int, loglen+1)
	Lvals := make([]ECPoint, loglen)
	Rvals := make([]ECPoint, loglen)

	runningProof := InnerProdArg{
		Lvals,
		Rvals,
		challenges,
		big.NewInt(0),
		big.NewInt(0)}

	// randomly generate an x value from public data
	x := sha256.Sum256([]byte(P.X.String() + P.Y.String()))

	runningProof.x[loglen] = new(big.Int).SetBytes(x[:])

	Pprime := P.Add(CP.U.Mult(new(big.Int).Mul(new(big.Int).SetBytes(x[:]), c)))
	ux := CP.U.Mult(new(big.Int).SetBytes(x[:]))
	//fmt.Printf("Prover Pprime value to run sub off of: %s\n", Pprime)
	return InnerProductProveSub(runningProof, CP.G, CP.H, a, b, ux, Pprime)
}

/* Inner Product Verify
Given a inner product proof, verifies the correctness of the proof

Since we're using the Fiat-Shamir transform, we need to verify all x hash computations,
all g' and h' computations

P : the Pedersen commitment we are verifying is a commitment to the innner product
ipp : the proof

 */
func InnerProductVerify(c *big.Int, P ECPoint, ipp InnerProdArg) bool{
	fmt.Println("Verifying Inner Product Argument")
	 fmt.Printf("Commitment Value: %s \n", P)
	 s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	 chal1 := new(big.Int).SetBytes(s1[:])
	 curIt := len(ipp.x)-1

	 if ipp.x[curIt].Cmp(chal1) != 0 {
	 	println("IPVerify - Initial Challenge Failed")
	 	return false
	 }

	 curIt -= 1

	 Gprime := CP.G
	 Hprime := CP.H
	 Pprime := P.Add(CP.U.Mult(new(big.Int).Mul(chal1, c))) // line 6 from protocol 1
	 //fmt.Printf("New Commitment value with u^cx: %s \n", Pprime)
	 for curIt >= 0 {
	 	Lval := ipp.L[curIt]
	 	Rval := ipp.R[curIt]

		 // prover sends L & R and gets a challenge
		 s256 := sha256.Sum256([]byte(
			 Lval.X.String() + Lval.Y.String() +
				 Rval.X.String() + Rval.Y.String()))

		 chal2 := new(big.Int).SetBytes(s256[:])

		 if ipp.x[curIt].Cmp(chal2) != 0 {
		 	println("IPVerify - Challenge verification failed at index " + strconv.Itoa(curIt))
		 	return false
		 }

		 Gprime, Hprime, Pprime = GenerateNewParams(Gprime, Hprime, chal2, Lval, Rval, Pprime)

	 	curIt -= 1
	 }

	ccalc := new(big.Int).Mul(ipp.a, ipp.b)

	Pcalc := Gprime[0].Mult(ipp.a).Add(Hprime[0].Mult(ipp.b)).Add(CP.U.Mult(new(big.Int).Mul(chal1, ccalc)))
	fmt.Printf("Final Pprime value: %s \n", Pprime)
	fmt.Printf("Calculated Pprime value to check against: %s \n", Pcalc)

	if !Pprime.Equal(Pcalc) {
		println("IPVerify - Final Commitment checking failed")
		return false
	}


	return true
}

type RangeProof struct {
	A		ECPoint
	S 		ECPoint
	T1 		ECPoint
	T2		ECPoint
	L 		[]ECPoint
	R 		[]ECPoint
	tau 	*big.Int
	th 		*big.Int
	mu 		*big.Int
	a 		*big.Int
	b 		*big.Int

	// challenges
	cy 		*big.Int
	cz 		*big.Int
	cx 		*big.Int
	cxu 	*big.Int
	cxi 	[]*big.Int
}


func RPProve(v *big.Int) RangeProof {

	// break up v into its bitwise representation
	//aL := 0

	return RangeProof{}
}

func RPVerify(rp RangeProof) bool {
	// verify the challenges


	return false
}

// NewECPrimeGroupKey returns the curve (field),
// Generator 1 x&y, Generator 2 x&y, order of the generators
func NewECPrimeGroupKey(n int) CryptoParams {
	curValue := btcec.S256().Gx
	s256 := sha256.New()
	gen1Vals := make([]ECPoint, n)
	gen2Vals := make([]ECPoint, n)
	u := ECPoint{big.NewInt(0), big.NewInt(0)}

	j := 0;
	confirmed := 0;
	for confirmed < (2*n + 1) {
		s256.Write(new(big.Int).Add(curValue, big.NewInt(int64(j))).Bytes())

		potentialXValue := make([]byte, 33)
		binary.LittleEndian.PutUint32(potentialXValue, 2)
		for i, elem := range s256.Sum(nil) {
			potentialXValue[i+1] = elem
		}

		gen2, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
		if err == nil{
			if confirmed == 2*n{ // once we've generated all g and h values then assign this to u
				u = ECPoint{gen2.X, gen2.Y}
				//println("Got that U value")
			} else {
				if confirmed%2 == 0 {
					gen1Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
					//println("new G Value")
				} else {
					gen2Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
					//println("new H value")
				}
			}
			confirmed += 1;
		}
		j += 1;
	}

	return CryptoParams{
		btcec.S256(),
		btcec.S256(),
		gen1Vals,
		gen2Vals,
		btcec.S256().N,
		u,
		n}
}



func init() {
	CP = NewECPrimeGroupKey(VecLength)
	//fmt.Println(CP)
}