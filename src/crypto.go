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
var VecLength = 64
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
	modValue := negY.Mod(negY, CP.C.Params().P) // mod P is fine here because we're describing a curve point
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
	CG ECPoint			// G value for commitments of a single value
	CH ECPoint			// H value for commitments of a single value
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
	if len(a) != len(b) {
		fmt.Println("TwoVectorPCommit: Uh oh! Arrays not of the same length")
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	commitment := CP.Zero()

	for i := 0; i < CP.V; i++{
		commitment = commitment.Add(CP.G[i].Mult(a[i])).Add(CP.H[i].Mult(b[i]))
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
	if len(G) != len(H) || len(G) != len(a) || len(a) != len(b) {
		fmt.Println("TwoVectorPCommitWithGens: Uh oh! Arrays not of the same length")
		fmt.Printf("len(G): %d\n", len(G))
		fmt.Printf("len(H): %d\n", len(H))
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	commitment := CP.Zero()

	for i := 0; i < len(G); i++{
		modA := new(big.Int).Mod(a[i], CP.N)
		modB := new(big.Int).Mod(b[i], CP.N)

		commitment = commitment.Add(G[i].Mult(modA)).Add(H[i].Mult(modB))
	}

	return commitment
}


// The length here always has to be a power of two
func InnerProduct(a []*big.Int, b []*big.Int) *big.Int {
	if len(a) != len(b) {
		fmt.Println("InnerProduct: Uh oh! Arrays not of the same length")
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	c := big.NewInt(0)

	for i := range a{
		tmp1 := new(big.Int).Mul(a[i], b[i])
		c = new(big.Int).Add(c, new(big.Int).Mod(tmp1, CP.N))
	}

	return new(big.Int).Mod(c, CP.N)
}

func VectorAdd(v []*big.Int, w []*big.Int) []*big.Int {
	if len(v) != len(w) {
		fmt.Println("VectorAdd: Uh oh! Arrays not of the same length")
		fmt.Printf("len(v): %d\n", len(v))
		fmt.Printf("len(w): %d\n", len(w))
	}
	result := make([]*big.Int, len(v))

	for i := range v{
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], w[i]), CP.N)
	}

	return result
}

func VectorHadamard(v, w []*big.Int) []*big.Int {
	if len(v) != len(w) {
		fmt.Println("VectorHadamard: Uh oh! Arrays not of the same length")
		fmt.Printf("len(v): %d\n", len(w))
		fmt.Printf("len(w): %d\n", len(v))
	}

	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], w[i]), CP.N)
	}

	return result
}

func VectorAddScalar(v []*big.Int, s *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], s), CP.N)
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
	A	*big.Int
	B 	*big.Int

	Challenges 	[]*big.Int
}

func GenerateNewParams(G, H []ECPoint, x *big.Int, L, R, P ECPoint) ([]ECPoint, []ECPoint, ECPoint){
	nprime := len(G)/2

	Gprime := make([]ECPoint, nprime)
	Hprime := make([]ECPoint, nprime)

	xinv := new(big.Int).ModInverse(x, CP.N)

	// Gprime = xinv * G[:nprime] + x*G[nprime:]
	// Hprime = x * H[:nprime] + xinv*H[nprime:]

	for i := range Gprime {
		//fmt.Printf("i: %d && i+nprime: %d\n", i, i+nprime)
		Gprime[i] = G[i].Mult(xinv).Add(G[i+nprime].Mult(x))
		Hprime[i] = H[i].Mult(x).Add(H[i+nprime].Mult(xinv))
	}

	x2 := new(big.Int).Mod(new(big.Int).Mul(x, x), CP.N)
	xinv2 := new(big.Int).ModInverse(x2, CP.N)

	Pprime := L.Mult(x2).Add(P).Add(R.Mult(xinv2)) // x^2 * L + P + xinv^2 * R

	return Gprime, Hprime, Pprime
}

/* Inner Product Argument

Proves that <a,b>=c

This is a building block for BulletProofs

*/
func InnerProductProveSub(proof InnerProdArg, G, H []ECPoint, a []*big.Int, b []*big.Int, u ECPoint, P ECPoint) InnerProdArg {
	//fmt.Printf("Proof so far: %s\n", proof)
	if len(a) == 1{
		// Prover sends a & b
		//fmt.Printf("a: %d && b: %d\n", a[0], b[0])
		proof.A = a[0]
		proof.B = b[0]
		return proof
	}

	curIt := int(math.Log2(float64(len(a))))-1

	nprime := len(a)/2
	//println(nprime)
	//println(len(H))
	cl := InnerProduct(a[:nprime], b[nprime:]) // either this line
	cr := InnerProduct(a[nprime:], b[:nprime]) // or this line
	L := TwoVectorPCommitWithGens(G[nprime:], H[:nprime], a[:nprime], b[nprime:]).Add(u.Mult(cl))
	R := TwoVectorPCommitWithGens(G[:nprime], H[nprime:], a[nprime:], b[:nprime]).Add(u.Mult(cr))

	proof.L[curIt] = L
	proof.R[curIt] = R

	// prover sends L & R and gets a challenge
	s256 := sha256.Sum256([]byte(
				L.X.String() + L.Y.String() +
				R.X.String() + R.Y.String()))

	x := new(big.Int).SetBytes(s256[:])

	proof.Challenges[curIt] = x

	Gprime, Hprime, Pprime := GenerateNewParams(G, H, x, L, R, P)
	//fmt.Printf("Prover - Intermediate Pprime value: %s \n", Pprime)
	xinv := new(big.Int).ModInverse(x, CP.N)

	// or these two lines
	aprime := VectorAdd(
		ScalarVectorMul(a[:nprime], x),
		ScalarVectorMul(a[nprime:], xinv))
	bprime := VectorAdd(
		ScalarVectorMul(b[:nprime], xinv),
		ScalarVectorMul(b[nprime:], x))

	return InnerProductProveSub(proof, Gprime, Hprime, aprime, bprime, u, Pprime)
}

func InnerProductProve(a []*big.Int, b []*big.Int, c *big.Int, P, U ECPoint, G, H []ECPoint) InnerProdArg {
	loglen := int(math.Log2(float64(len(a))))

	challenges := make([]*big.Int, loglen+1)
	Lvals := make([]ECPoint, loglen)
	Rvals := make([]ECPoint, loglen)

	runningProof := InnerProdArg{
		Lvals,
		Rvals,
		big.NewInt(0),
		big.NewInt(0),
		challenges}

	// randomly generate an x value from public data
	x := sha256.Sum256([]byte(P.X.String() + P.Y.String()))

	runningProof.Challenges[loglen] = new(big.Int).SetBytes(x[:])

	Pprime := P.Add(U.Mult(new(big.Int).Mul(new(big.Int).SetBytes(x[:]), c)))
	ux := U.Mult(new(big.Int).SetBytes(x[:]))
	//fmt.Printf("Prover Pprime value to run sub off of: %s\n", Pprime)
	return InnerProductProveSub(runningProof, G, H, a, b, ux, Pprime)
}

/* Inner Product Verify
Given a inner product proof, verifies the correctness of the proof

Since we're using the Fiat-Shamir transform, we need to verify all x hash computations,
all g' and h' computations

P : the Pedersen commitment we are verifying is a commitment to the innner product
ipp : the proof

 */
func InnerProductVerify(c *big.Int, P, U ECPoint, ipp InnerProdArg) bool{
	 //fmt.Println("Verifying Inner Product Argument")
	 //fmt.Printf("Commitment Value: %s \n", P)
	 s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	 chal1 := new(big.Int).SetBytes(s1[:])
	 ux := U.Mult(chal1)
	 curIt := len(ipp.Challenges)-1

	 if ipp.Challenges[curIt].Cmp(chal1) != 0 {
	 	println("IPVerify - Initial Challenge Failed")
	 	return false
	 }

	 curIt -= 1

	 Gprime := CP.G
	 Hprime := CP.H
	 Pprime := P.Add(ux.Mult(c)) // line 6 from protocol 1
	 //fmt.Printf("New Commitment value with u^cx: %s \n", Pprime)

	 for curIt >= 0 {
	 	Lval := ipp.L[curIt]
	 	Rval := ipp.R[curIt]

		 // prover sends L & R and gets a challenge
		 s256 := sha256.Sum256([]byte(
			 Lval.X.String() + Lval.Y.String() +
			 Rval.X.String() + Rval.Y.String()))

		 chal2 := new(big.Int).SetBytes(s256[:])

		 if ipp.Challenges[curIt].Cmp(chal2) != 0 {
		 	println("IPVerify - Challenge verification failed at index " + strconv.Itoa(curIt))
		 	return false
		 }

		 Gprime, Hprime, Pprime = GenerateNewParams(Gprime, Hprime, chal2, Lval, Rval, Pprime)
	 	curIt -= 1
	 }
	ccalc := new(big.Int).Mod(new(big.Int).Mul(ipp.A, ipp.B), CP.N)

	Pcalc1 := Gprime[0].Mult(ipp.A)
	Pcalc2 := Hprime[0].Mult(ipp.B)
	Pcalc3 := ux.Mult(ccalc)
	Pcalc := Pcalc1.Add(Pcalc2).Add(Pcalc3)


	//fmt.Printf("Final Pprime value: %s \n", Pprime)
	//fmt.Printf("Calculated Pprime value to check against: %s \n", Pcalc)

	if !Pprime.Equal(Pcalc) {
		println("IPVerify - Final Commitment checking failed")
		return false
	}


	return true
}

// from here: https://play.golang.org/p/zciRZvD0Gr with a fix
func PadLeft(str, pad string, l int) string {
	strCopy := str
	for len(strCopy) < l {
		strCopy = pad + strCopy
	}

	return strCopy
}

func STRNot(str string) string {
	result := ""

	for _,i := range str{
		if i == '0' {
			result += "1"
		} else {
			result += "0"
		}
	}

	return result
}

func StrToBigIntArray(str string) []*big.Int {
	result := make([]*big.Int, len(str))

	for i := range str {
		t, success := new(big.Int).SetString(string(str[i]), 10)
		if success {
			result[i] = t
		}
	}

	return result
}

func reverse(l []*big.Int) []*big.Int {
	result := make([]*big.Int, len(l))

	for i := range(l){
		result[i] = l[len(l)-i-1]
	}

	return result
}

/*
Delta is a helper function that is used in the range proof

\delta(y, z) = (z-z^2)<1^n, y^n> - z^3<1^n, 2^n>
 */

func Delta(y []*big.Int, z *big.Int) *big.Int {
	result := big.NewInt(0)

	// (z-z^2)<1^n, y^n>
	z2 := new(big.Int).Mod(new(big.Int).Mul(z, z), CP.N)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, z2), CP.N)
	t2 := new(big.Int).Mod(new(big.Int).Mul(t1, VectorSum(y)), CP.N)

	// z^3<1^n, 2^n>
	z3 := new(big.Int).Mod(new(big.Int).Mul(z2, z), CP.N)
	po2sum := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(64), CP.N), big.NewInt(1))
	t3 := new(big.Int).Mod(new(big.Int).Mul(z3, po2sum), CP.N)

	result = new(big.Int).Mod(new(big.Int).Sub(t2, t3), CP.N)

	return result
}

func PowerVector(l int, base *big.Int) []*big.Int {
	result := make([]*big.Int, l)

	for i := 0; i < l; i++{
		result[i] = new(big.Int).Exp(base, big.NewInt(int64(i)), CP.N)
	}

	return result
}

func RandVector(l int) []*big.Int {
	result := make([]*big.Int, l)

	for i := 0; i < l; i++ {
		x, err := rand.Int(rand.Reader, CP.N)
		check(err)
		result[i] = x
	}

	return result
}

func VectorSum(y []*big.Int) *big.Int{
	result := big.NewInt(0)

	for _,j := range y {
		result = new(big.Int).Mod(new(big.Int).Add(result, j), CP.N)
	}

	return result
}

type RangeProof struct {
	Comm 	ECPoint
	A		ECPoint
	S 		ECPoint
	T1 		ECPoint
	T2		ECPoint
	Tau 	*big.Int
	Th 		*big.Int
	Mu 		*big.Int
	IPP 	InnerProdArg

	// challenges
	Cy 		*big.Int
	Cz 		*big.Int
	Cx 		*big.Int

}


// Calculates (aL - z*1^n) + sL*x
func CalculateL(aL, sL []*big.Int, z, x *big.Int) []*big.Int {
	result := make([]*big.Int, len(aL))

	tmp1 := VectorAddScalar(aL, new(big.Int).Neg(z))
	tmp2 := ScalarVectorMul(sL, x)

	result = VectorAdd(tmp1, tmp2)

	return result
}

func CalculateR(aR, sR, y, po2 []*big.Int, z, x *big.Int) []*big.Int {
	if len(aR) != len(sR) || len(aR) != len(y) || len(y) != len(po2) {
		fmt.Println("CalculateR: Uh oh! Arrays not of the same length")
		fmt.Printf("len(aR): %d\n", len(aR))
		fmt.Printf("len(sR): %d\n", len(sR))
		fmt.Printf("len(y): %d\n", len(y))
		fmt.Printf("len(po2): %d\n", len(po2))
	}

	result := make([]*big.Int, len(aR))

	z2 := new(big.Int).Exp(z, big.NewInt(2), CP.N)
	tmp11 := VectorAddScalar(aR, z)
	tmp12 := ScalarVectorMul(sR, x)
	tmp1 := VectorHadamard(y, VectorAdd(tmp11,tmp12))
	tmp2 := ScalarVectorMul(po2, z2)

	result = VectorAdd(tmp1, tmp2)

	return result
}


/*
RPProver : Range Proof Prove

Given a value v, provides a range proof that v is inside 0 to 2^64-1
 */
func RPProve(v *big.Int) RangeProof {

	rpresult := RangeProof{}

	PowerOfTwos := PowerVector(64, big.NewInt(2))


	if v.Cmp(big.NewInt(0)) == -1 {
		panic("Value is below range! Not proving")
	}

	if v.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(64), CP.N)) == 1 {
		panic("Value is above range! Not proving.")
	}

	gamma, err := rand.Int(rand.Reader, CP.N)
	check(err)
	comm := CP.CG.Mult(v).Add(CP.CH.Mult(gamma))
	rpresult.Comm = comm

	// break up v into its bitwise representation
	//aL := 0
	aL := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", 64)))
	aR := VectorAddScalar(aL, big.NewInt(-1))

	alpha, err := rand.Int(rand.Reader, CP.N)
	check(err)

	A := TwoVectorPCommit(aL, aR).Add(CP.CH.Mult(alpha))
	rpresult.A = A

	sL := RandVector(64)
	sR := RandVector(64)

	rho, err := rand.Int(rand.Reader, CP.N)
	check(err)

	S := TwoVectorPCommit(sL, sR).Add(CP.CH.Mult(rho))
	rpresult.S = S

	chal1s256 := sha256.Sum256([]byte(A.X.String() + A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	rpresult.Cy = cy

	chal2s256 := sha256.Sum256([]byte(S.X.String() + S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	rpresult.Cz = cz
	z2 := new(big.Int).Exp(cz, big.NewInt(2), CP.N)
	// need to generate l(X), r(X), and t(X)=<l(X),r(X)>

	/*
	Java code on how to calculate t1 and t2

		FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply),q); //powers of y
	    FieldVector l0 = aL.add(z.negate());
        FieldVector l1 = sL;
        FieldVector twoTimesZSquared = twos.times(zSquared);
        FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZSquared);
        FieldVector r1 = sR.hadamard(ys);
        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
        BigInteger t0 = k.add(zSquared.multiply(number));
        BigInteger t1 = l1.innerPoduct(r0).add(l0.innerPoduct(r1));
        BigInteger t2 = l1.innerPoduct(r1);
   		PolyCommitment<T> polyCommitment = PolyCommitment.from(base, t0, VectorX.of(t1, t2));


	 */
	PowerOfCY := PowerVector(64, cy)
	// fmt.Println(PowerOfCY)
	l0 := VectorAddScalar(aL, new(big.Int).Neg(cz))
	// l1 := sL
	r0 := VectorAdd(
		VectorHadamard(
			PowerOfCY,
			VectorAddScalar(aR, cz)),
		ScalarVectorMul(
			PowerOfTwos,
			z2))
	r1 := VectorHadamard(sR, PowerOfCY)

	//calculate t0
	t0 := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(v, z2), Delta(PowerOfCY, cz)),CP.N)

	t1 := new(big.Int).Mod(new(big.Int).Add(InnerProduct(sL, r0), InnerProduct(l0, r1)), CP.N)
	t2 := InnerProduct(sL, r1)

	// given the t_i values, we can generate commitments to them
	tau1, err := rand.Int(rand.Reader, CP.N)
	check(err)
	tau2, err := rand.Int(rand.Reader, CP.N)
	check(err)

	T1 := CP.CG.Mult(t1).Add(CP.CH.Mult(tau1)) //commitment to t1
	T2 := CP.CG.Mult(t2).Add(CP.CH.Mult(tau2)) //commitment to t2

	rpresult.T1 = T1
	rpresult.T2 = T2

	chal3s256 := sha256.Sum256([]byte(T1.X.String() + T1.Y.String() + T2.X.String() + T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])

	rpresult.Cx = cx

	left := CalculateL(aL, sL, cz, cx)
	right := CalculateR(aR, sR, PowerOfCY, PowerOfTwos, cz, cx)

	thatPrime := new(big.Int).Mod( // t0 + t1*x + t2*x^2
		new(big.Int).Add(
			t0,
			new(big.Int).Add(
				new(big.Int).Mul(
					t1, cx),
					new(big.Int).Mul(
						new(big.Int).Mul(cx,cx),
						t2))), CP.N)

	that := InnerProduct(left, right) // NOTE: BP Java implementation calculates this from the t_i

	// thatPrime and that should be equal
	if thatPrime.Cmp(that) != 0 {
		fmt.Println("Proving -- Uh oh! Two diff ways to compute same value not working")
		fmt.Printf("\tthatPrime = %s\n", thatPrime.String())
		fmt.Printf("\tthat = %s \n", that.String())
	}

	rpresult.Th = thatPrime

	taux1 := new(big.Int).Mod(new(big.Int).Mul(tau2, new(big.Int).Mul(cx, cx)), CP.N)
	taux2 := new(big.Int).Mod(new(big.Int).Mul(tau1, cx), CP.N)
	taux3 := new(big.Int).Mod(new(big.Int).Mul(z2, gamma), CP.N)
	taux := new(big.Int).Mod(new(big.Int).Add(taux1, new(big.Int).Add(taux2, taux3)), CP.N)

	rpresult.Tau = taux

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, cx)), CP.N)
	rpresult.Mu = mu

	
	HPrime := make([]ECPoint, len(CP.H))

	for i := range HPrime {
		HPrime[i] = CP.H[i].Mult(new(big.Int).ModInverse(PowerOfCY[i], CP.N))
	}
	P := TwoVectorPCommitWithGens(CP.G, HPrime, left, right)
	//fmt.Println(P)
	rpresult.IPP = InnerProductProve(left, right, that, P, CP.CH, CP.G, HPrime)

	//fmt.Println(rpresult)

	return rpresult
}

func RPVerify(rp RangeProof) bool {
	// verify the challenges
	chal1s256 := sha256.Sum256([]byte(rp.A.X.String() + rp.A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])
	if cy.Cmp(rp.Cy) != 0 {
		fmt.Println("RPVerify - Challenge Cy failing!")
		return false
	}
	chal2s256 := sha256.Sum256([]byte(rp.S.X.String() + rp.S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])
	if cz.Cmp(rp.Cz) != 0 {
		fmt.Println("RPVerify - Challenge Cz failing!")
		return false
	}
	chal3s256 := sha256.Sum256([]byte(rp.T1.X.String() + rp.T1.Y.String() + rp.T2.X.String() + rp.T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])
	if cx.Cmp(rp.Cx) != 0 {
		fmt.Println("RPVerify - Challenge Cx failing!")
		return false
	}

	// given challenges are correct, very range proof
	PowersOfY := PowerVector(64, cy)

	// t_hat * G + tau * H
	lhs := CP.CG.Mult(rp.Th).Add(CP.CH.Mult(rp.Tau))

	// z^2 * V + delta(y,z) * G + x * T1 + x^2 * T2
	rhs := rp.Comm.Mult(new(big.Int).Mul(cz, cz)).Add(
		CP.CG.Mult(Delta(PowersOfY, cz))).Add(
		rp.T1.Mult(cx)).Add(
		rp.T2.Mult(new(big.Int).Mul(cx, cx)))

	if !lhs.Equal(rhs){
		fmt.Println("RPVerify - Uh oh! Check line (63) of verification")
		fmt.Println(rhs)
		fmt.Println(lhs)
		return false
	}

	tmp1 := CP.Zero()
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), CP.N)
	for i := range CP.G {
		tmp1 = tmp1.Add(CP.G[i].Mult(zneg))
	}

	PowerOfTwos := PowerVector(64, big.NewInt(2))
	tmp2 := CP.Zero()
	// generate h'
	HPrime := make([]ECPoint, len(CP.H))

	for i := range HPrime {
		mi := new(big.Int).ModInverse(PowersOfY[i], CP.N)
		HPrime[i] = CP.H[i].Mult(mi)
	}

	for i := range HPrime {
		val1 := new(big.Int).Mul(cz, PowersOfY[i])
		val2 := new(big.Int).Mul(new(big.Int).Mul(cz, cz), PowerOfTwos[i])
		tmp2 = tmp2.Add(HPrime[i].Mult(new(big.Int).Add(val1, val2)))
	}

	P := rp.A.Add(rp.S.Mult(cx)).Add(tmp1).Add(tmp2)
	fmt.Println(P)

	if !InnerProductVerify(rp.Th, P, CP.CH.Mult(rp.Mu), rp.IPP) {
		fmt.Println("RPVerify - Uh oh! Check line (65) of verification!")
		return false
	}

	return true
}

// NewECPrimeGroupKey returns the curve (field),
// Generator 1 x&y, Generator 2 x&y, order of the generators
func NewECPrimeGroupKey(n int) CryptoParams {
	curValue := btcec.S256().Gx
	s256 := sha256.New()
	gen1Vals := make([]ECPoint, n)
	gen2Vals := make([]ECPoint, n)
	u := ECPoint{big.NewInt(0), big.NewInt(0)}
	cg := ECPoint{}
	ch := ECPoint{}


	j := 0
	confirmed := 0
	for confirmed < (2*n + 3) {
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
			} else if confirmed == 2*n +1 {
				cg = ECPoint{gen2.X, gen2.Y}

			} else if confirmed == 2*n + 2 {
				ch = ECPoint{gen2.X, gen2.Y}
			} else {
				if confirmed%2 == 0 {
					gen1Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
					//println("new G Value")
				} else {
					gen2Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
					//println("new H value")
				}
			}
			confirmed += 1
		}
		j += 1
	}

	return CryptoParams{
		btcec.S256(),
		btcec.S256(),
		gen1Vals,
		gen2Vals,
		btcec.S256().N,
		u,
		n,
		cg,
		ch}
}



func init() {
	CP = NewECPrimeGroupKey(VecLength)
	//fmt.Println(CP)
}