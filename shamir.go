package gnark

import (
	"Inskape/bls-shamir/core/exception"
	"context"
	"fmt"
	"slices"

	bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
)

// Implemented according to https://github.com/dashpay/dips/blob/master/dip-0006/bls_m-of-n_threshold_scheme_and_dkg.md

// Evaluates polynomial (coefficient tuple) at x, used to generate a shamir pool in make_random_shares below.
func EvaluatePolynomial(ctx context.Context, x fr.Element, coefficients []fr.Element) fr.Element {
	ctx, span := tracer.Start(ctx, "EvaluatePolynomial")
	defer span.End()

	if x.IsZero() {
		return coefficients[0]
	}

	out := elementPool.Get(ctx)
	defer elementPool.Put(ctx, out)

	if len(coefficients) == 0 {
		return *out.SetZero()
	}

	degree := len(coefficients) - 1
	out.Set(&coefficients[degree])

	for i := degree - 1; i >= 0; i-- {
		out.
			Mul(out, &x).
			Add(out, &coefficients[i])
	}
	return *out
}

// Evaluates polynomial in G1 (coefficient tuple) at x, used to generate a shamir pool in Split below.
func EvaluatePolynomialG1(ctx context.Context, x fr.Element, coefficients []bls24317.G1Affine) bls24317.G1Affine {
	ctx, span := tracer.Start(ctx, "EvaluatePolynomialG1")
	defer span.End()

	if x.IsZero() {
		return coefficients[0]
	}

	if len(coefficients) == 0 {
		return bls24317.G1Affine{}
	}

	degree := len(coefficients) - 1

	g1, bigInt := g1AffinePool.Get(ctx), bigIntPool.Get(ctx)
	defer bigIntPool.Put(ctx, bigInt)
	defer g1AffinePool.Put(ctx, g1)

	out := g1.Set(&coefficients[degree])

	for i := degree - 1; i >= 0; i-- {
		out.
			ScalarMultiplication(out, x.BigInt(bigInt)).
			Add(out, &coefficients[i])
	}
	return *out
}

// Generates a random shamir pool for a given secret, returns share points.
func Split(ctx context.Context, secret SecretKey, shareholders []PublicKey, threshold uint32) (shares map[PublicKey]SecretKey, publicCoefficients []bls24317.G1Affine, err error) {
	ctx, span := tracer.Start(ctx, "Split")
	defer span.End()

	if threshold > uint32(len(shareholders)+1) {
		return nil, nil, fmt.Errorf("%d shareholders cannot satisfy a threshold of %d", len(shareholders), threshold)
	}
	if threshold < 2 {
		return nil, nil, fmt.Errorf("threshold must be at least 2, got %d", threshold)
	}
	if secret.value.IsZero() {
		return nil, nil, fmt.Errorf("secret must be non-zero")
	}

	slices.SortFunc(shareholders, func(i, j PublicKey) int {
		return i.Cmp(j)
	})

	// Generate a random polynomial of degree threshold-1 coefficients are generated in the range [0, prime)
	coefficients := make([]fr.Element, threshold)
	publicCoefficients = make([]bls24317.G1Affine, threshold)
	coefficients[0] = secret.value
	publicCoefficients[0] = secret.PublicKey(ctx).value
	element := elementPool.Get(ctx)
	defer elementPool.Put(ctx, element)
	for i := uint32(1); i < threshold; i++ {
		c, err := element.SetRandom()
		if err != nil {
			return nil, nil, err
		}
		coefficients[i] = *c
		publicCoefficients[i] = SecretKey{value: coefficients[i]}.PublicKey(ctx).value
	}

	// Evaluate the polynomial at each of the shareholders and add the results to a list of points
	shares = make(map[PublicKey]SecretKey, len(shareholders))
	for _, shareholder := range shareholders {
		l := EvaluatePolynomial(ctx, shareholder.ToElement(ctx), coefficients)
		share := SecretKey{
			value: l,
		}
		otherP := share.PublicKey(ctx).value
		if p := EvaluatePolynomialG1(ctx, shareholder.ToElement(ctx), publicCoefficients); !p.Equal(&otherP) {
			return nil, nil, fmt.Errorf("public key != evaluated public key (%s != %s) for %s", PublicKey{value: p}.String(), share.PublicKey(ctx).String(), shareholder)
		} else {
			shares[shareholder] = share
		}
	}
	return shares, publicCoefficients, nil
}

func interpolate(ctx context.Context, x fr.Element, shares map[PublicKey]SecretKey) fr.Element {
	ctx, span := tracer.Start(ctx, "interpolate")
	defer span.End()

	result := elementPool.Get(ctx).SetZero()
	defer elementPool.Put(ctx, result)

	basis, num, den, group := elementPool.Get(ctx), elementPool.Get(ctx), elementPool.Get(ctx), elementPool.Get(ctx)
	defer elementPool.Put(ctx, basis)
	defer elementPool.Put(ctx, num)
	defer elementPool.Put(ctx, den)
	defer elementPool.Put(ctx, group)

	for x_i, y_i := range shares {
		xi := x_i.ToElement(ctx)
		basis.SetOne()
		for x_j := range shares {
			if x_i.Equals(x_j) {
				continue
			}
			xj := x_j.ToElement(ctx)
			num.Sub(&x, &xj)
			den.Sub(&xi, &xj)
			basis.Mul(basis, num.Div(num, den))
		}
		group.Mul(basis, &y_i.value)
		result.Add(result, group)
	}
	return *result
}

// Recover the secret from share points (x, y points on the polynomial).
func RecoverSecretKey(ctx context.Context, shares map[PublicKey]SecretKey) (SecretKey, error) {
	ctx, span := tracer.Start(ctx, "RecoverSecretKey")
	defer span.End()

	if len(shares) < 2 {
		return NewSecretKey(), fmt.Errorf("must have at least 2 shares")
	}
	element := elementPool.Get(ctx)
	defer elementPool.Put(ctx, element)

	result := SecretKey{
		value: interpolate(ctx, *element.SetZero(), shares),
	}
	return result, nil
}

func g1Identity() *bls24317.G1Jac {
	// Set identity point
	result := new(bls24317.G1Jac)
	result.X.SetZero()
	result.Y.SetOne()
	result.Z.SetZero()
	return result
}

func interpolateG1(ctx context.Context, x *fr.Element, pubKeys map[PublicKey]PublicKey) bls24317.G1Jac {
	ctx, span := tracer.Start(ctx, "interpolateG1")
	defer span.End()

	result := g1Identity()

	bigInt, basis, num, den, yi, group := bigIntPool.Get(ctx), elementPool.Get(ctx), elementPool.Get(ctx), elementPool.Get(ctx), g1JacPool.Get(ctx), g1JacPool.Get(ctx)
	defer bigIntPool.Put(ctx, bigInt)
	defer elementPool.Put(ctx, basis)
	defer elementPool.Put(ctx, num)
	defer elementPool.Put(ctx, den)
	defer g1JacPool.Put(ctx, yi)
	defer g1JacPool.Put(ctx, group)

	for x_i, y_i := range pubKeys {
		xi := x_i.ToElement(ctx)
		basis := basis.SetOne()

		for x_j := range pubKeys {
			if x_i.Equals(x_j) {
				continue
			}
			xj := x_j.ToElement(ctx)
			num.Sub(x, &xj)
			den.Sub(&xi, &xj)
			basis.Mul(basis, num.Div(num, den))
		}
		group.ScalarMultiplication(yi.FromAffine(&y_i.value), basis.BigInt(bigInt))
		result.AddAssign(group)
	}
	return *result
}

// Accept a set of public keys  and return the combined Shamir public key.
// https://db2510.github.io/blogs/aggregation/
func RecoverPublicKey(ctx context.Context, publicKeys map[PublicKey]PublicKey) (*PublicKey, error) {
	ctx, span := tracer.Start(ctx, "RecoverPublicKey")
	defer span.End()

	if len(publicKeys) < 1 {
		return nil, fmt.Errorf("must have at least 2 shares")
	}

	x, g1 := elementPool.Get(ctx).SetZero(), g1AffinePool.Get(ctx)
	defer elementPool.Put(ctx, x)
	defer g1AffinePool.Put(ctx, g1)

	l := interpolateG1(ctx, x, publicKeys)
	return &PublicKey{
		value: *g1.FromJacobian(&l),
	}, nil
}

func interpolateG1Slice[T ~[]bls24317.G1Affine](ctx context.Context, x *fr.Element, pubKeys map[PublicKey]T) T {
	ctx, span := tracer.Start(ctx, "interpolateG1Slice")
	defer span.End()

	degree := len(pubKeys) - 1
	result := make(T, degree)

	// interpolate each coefficient degree to create a new threshold polynomial
	coefficients := make(map[PublicKey]PublicKey, len(pubKeys))
	tmp := g1AffinePool.Get(ctx)
	defer g1AffinePool.Put(ctx, tmp)

	for i := 0; i < degree; i++ {
		for k, v := range pubKeys {
			if degree != len(v) {
				degree = len(v)
			}
			coefficients[k] = NewPublicKeyFromG1(v[i])
		}
		r := interpolateG1(ctx, x, coefficients)
		result[i] = *tmp.FromJacobian(&r)
	}

	return result
}

func RecoverCoefficients[T ~[]bls24317.G1Affine](ctx context.Context, pubKeys map[PublicKey]T) (T, error) {
	ctx, span := tracer.Start(ctx, "RecoverCoefficients")
	defer span.End()

	if len(pubKeys) < 1 {
		return nil, fmt.Errorf("must have at least 2 shares")
	}

	x := elementPool.Get(ctx).SetZero()
	defer elementPool.Put(ctx, x)

	return interpolateG1Slice(ctx, x, pubKeys), nil
}

func g2Identity() *bls24317.G2Jac {
	// Set identity point
	result := new(bls24317.G2Jac)
	result.X.SetZero()
	result.Y.SetOne()
	result.Z.SetZero()
	return result
}

func interpolateG2(ctx context.Context, x *fr.Element, signatures map[PublicKey]Signature) bls24317.G2Jac {
	ctx, span := tracer.Start(ctx, "interpolateG2")
	defer span.End()

	result := g2Identity()

	bigInt, basis, num, den, yi, group := bigIntPool.Get(ctx), elementPool.Get(ctx), elementPool.Get(ctx), elementPool.Get(ctx), g2JacPool.Get(ctx), g2JacPool.Get(ctx)
	defer bigIntPool.Put(ctx, bigInt)
	defer elementPool.Put(ctx, basis)
	defer elementPool.Put(ctx, num)
	defer elementPool.Put(ctx, den)
	defer g2JacPool.Put(ctx, yi)
	defer g2JacPool.Put(ctx, group)

	for x_i, y_i := range signatures {
		xi := x_i.ToElement(ctx)
		basis.SetOne()
		for x_j := range signatures {
			if x_i.Equals(x_j) {
				continue
			}
			xj := x_j.ToElement(ctx)
			num.Sub(x, &xj)
			den.Sub(&xi, &xj)
			basis.Mul(basis, num.Div(num, den))
		}
		group.ScalarMultiplication(yi.FromAffine(&y_i.value), basis.BigInt(bigInt))
		result.AddAssign(group)
	}

	return *result
}

// Accept a set of signatures (a G2 point and an F element) and return the combined Shamir signature that is compatible with the distributed public key.
// https://db2510.github.io/blogs/aggregation/
func RecoverSignature(ctx context.Context, signatures map[PublicKey]Signature) (Signature, error) {
	ctx, span := tracer.Start(ctx, "RecoverSignature")
	defer span.End()

	if len(signatures) < 1 {
		return NewSignature(), exception.ErrInvalidSignature().WithDetail("must have at least 2 signatures")
	}
	x, g2 := elementPool.Get(ctx).SetZero(), g2AffinePool.Get(ctx)
	defer elementPool.Put(ctx, x)
	defer g2AffinePool.Put(ctx, g2)

	l := interpolateG2(ctx, x, signatures)
	return Signature{
		value: *g2.FromJacobian(&l),
	}, nil
}
