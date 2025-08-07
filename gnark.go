package gnark

import (
	"Inskape/bls-shamir/core/atomic"
	"Inskape/bls-shamir/core/exception"
	"Inskape/bls-shamir/internal/encode"
	"Inskape/bls-shamir/internal/global"
	"bytes"
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"
	"time"

	bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/hkdf"
)

const (
	MinIKMLength = 32
	SecretKeyLen = fr.Bytes
	PublicKeyLen = bls24317.SizeOfG1AffineCompressed
	SignatureLen = bls24317.SizeOfG2AffineCompressed
)

const (
	keyGenSalt = "BLS-SIG-KEYGEN-SALT-"
	// Domain separation tag for basic signatures
	// according to section 4.2.1 in
	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
	signatureBasicDst = "BLS_SIG_BLS24317G2_XMD:SHA-256_SSWU_RO_NUL_"
	// Domain separation tag for augmented signatures
	// according to section 4.2.2 in
	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
	// signatureAugDst = "BLS_SIG_BLS24317G2_XMD:SHA-256_SSWU_RO_AUG_"
	// Domain separation tag for proof of possession signatures
	// according to section 4.2.3 in
	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
	// signaturePopDst = "BLS_SIG_BLS24317G2_XMD:SHA-256_SSWU_RO_POP_"
	// Domain separation tag for proof of possession proofs
	// according to section 4.2.3 in
	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
	// popProofDst = "BLS_POP_BLS24317G2_XMD:SHA-256_SSWU_RO_POP_"
)

const (
	poolItemTTL = 30 * time.Minute
)

var (
	tracer = otel.Tracer(global.Name + ":gnark")
)

var (
	_, _, g1AffineGenerator, _ = bls24317.Generators()
	hashFunc                   = sha512.New()
	bigIntPool                 = atomic.NewPool(poolItemTTL, func() *big.Int {
		return new(big.Int)
	})
	elementPool = atomic.NewPool(poolItemTTL, func() *fr.Element {
		return new(fr.Element)
	})
	g1AffinePool = atomic.NewPool(poolItemTTL, func() *bls24317.G1Affine {
		return new(bls24317.G1Affine)
	})
	g1JacPool = atomic.NewPool(poolItemTTL, func() *bls24317.G1Jac {
		return new(bls24317.G1Jac)
	})
	g2AffinePool = atomic.NewPool(poolItemTTL, func() *bls24317.G2Affine {
		return new(bls24317.G2Affine)
	})
	g2JacPool = atomic.NewPool(poolItemTTL, func() *bls24317.G2Jac {
		return new(bls24317.G2Jac)
	})
)

func GenerateKey(rand io.Reader) (SecretKey, error) {
	buf := make([]byte, MinIKMLength)
	n, err := rand.Read(buf)
	if err != nil {
		return NewSecretKey(), err
	}
	if n < MinIKMLength {
		return NewSecretKey(), fmt.Errorf("ikm length must be >= 32 bytes (read %d)", n)
	}
	return GenerateKeyWithSeed(buf)
}

func GenerateKeyWithSeed(ikm []byte) (SecretKey, error) {
	if len(ikm) < MinIKMLength {
		return NewSecretKey(), fmt.Errorf("ikm is too short. Must be at least 32")
	}

	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
	hashFunc.Reset()
	n, err := hashFunc.Write([]byte(keyGenSalt))
	if err != nil {
		return NewSecretKey(), err
	}
	if n != len(keyGenSalt) {
		return NewSecretKey(), fmt.Errorf("incorrect salt bytes written to be hashed")
	}
	salt := hashFunc.Sum(nil)

	ikm = append(ikm, 0)
	// Leaves key_info parameter as the default empty string
	// and just adds parameter I2OSP(L, 2)
	var okm [PublicKeyLen]byte
	kdf := hkdf.New(sha512.New, ikm, salt, []byte{0, PublicKeyLen})
	read, err := kdf.Read(okm[:])
	if err != nil {
		return NewSecretKey(), err
	}
	if read != PublicKeyLen {
		return NewSecretKey(), fmt.Errorf("failed to create private key")
	}
	copy(okm[:], reverseScalarBytes(okm[:]))
	v := new(fr.Element).SetBytes(okm[:])

	result := SecretKey{
		value: *v,
	}

	return result, nil
}

type SecretKey struct {
	value     fr.Element
	publicKey PublicKey
}

func NewSecretKey() SecretKey {
	return SecretKey{
		value: *new(fr.Element),
	}
}

func NewSecretKeyFromBytes(value []byte) SecretKey {
	return SecretKey{value: *new(fr.Element).SetBytes(value)}
}

func (sk SecretKey) Equals(other SecretKey) bool {
	return sk.value.Cmp(&other.value) == 0
}

func (sk SecretKey) Bytes() []byte {
	buf := sk.value.Bytes()
	return buf[:]
}

func (sk *SecretKey) SetBytes(buf []byte) *SecretKey {
	sk.value.SetBytes(buf)
	return sk
}

func (sk SecretKey) String() string {
	buf := sk.value.Bytes()
	return encode.Base64.EncodeToString(buf[:])
}

func (sk SecretKey) PublicKey(ctx context.Context) PublicKey {
	ctx, span := tracer.Start(ctx, "PublicKey")
	defer span.End()

	if !sk.value.IsZero() && !sk.publicKey.IsValid() {
		bigInt, g1 := bigIntPool.Get(ctx), g1AffinePool.Get(ctx)
		defer g1AffinePool.Put(ctx, g1)
		defer bigIntPool.Put(ctx, bigInt)
		pk := PublicKey{value: *g1.ScalarMultiplication(&g1AffineGenerator, sk.value.BigInt(bigInt))}
		if !pk.IsValid() {
			panic(fmt.Errorf("invalid public key computed"))
		}
		return pk
	}
	return sk.publicKey
}

func (sk SecretKey) Sign(ctx context.Context, message []byte) (Signature, error) {
	ctx, span := tracer.Start(ctx, "Sign")
	defer span.End()

	if message == nil {
		return NewSignature(), fmt.Errorf("message cannot be nil")
	}
	if sk.value.IsZero() {
		return NewSignature(), fmt.Errorf("invalid secret key")
	}
	p2, err := bls24317.EncodeToG2(message, []byte(signatureBasicDst))
	if err != nil {
		return NewSignature(), err
	}
	bigInt := bigIntPool.Get(ctx)
	defer bigIntPool.Put(ctx, bigInt)
	result := p2.ScalarMultiplication(&p2, sk.value.BigInt(bigInt))
	if !result.IsInSubGroup() {
		return NewSignature(), fmt.Errorf("point is not on correct subgroup")
	}
	return Signature{value: *result}, nil
}

type Signature struct {
	value bls24317.G2Affine
}

func NewSignature() Signature {
	return Signature{
		value: bls24317.G2Affine{},
	}
}

func NewSignatureFromBytes(value []byte) (Signature, error) {
	v := new(bls24317.G2Affine)

	if n, err := v.SetBytes(value); err != nil {
		return NewSignature(), exception.ErrInvalidPublicKeyBytes(err)
	} else if n != len(value) {
		return NewSignature(), exception.ErrInvalidPublicKeyBytes()
	} else {
		return Signature{value: *v}, nil
	}
}

func (s Signature) Bytes() []byte {
	buf := s.value.Bytes()
	return buf[:]
}

func (s *Signature) SetBytes(data []byte) (*Signature, error) {
	if _, err := s.value.SetBytes(data); err != nil {
		return nil, err
	}
	return s, nil
}

func (s Signature) String() string {
	buf := s.value.Bytes()
	return encode.Base64.EncodeToString(buf[:])
}

func (s Signature) Equals(other Signature) bool {
	return s.value.Equal(&other.value)
}

type PublicKey struct {
	value bls24317.G1Affine
}

func NewPublicKey() PublicKey {
	return PublicKey{
		value: bls24317.G1Affine{},
	}
}

func NewPublicKeyFromG1(value bls24317.G1Affine) PublicKey {
	return PublicKey{value: value}
}

func NewPublicKeyFromString(value string) (PublicKey, error) {
	v := new(bls24317.G1Affine)

	buf, err := encode.Base64.DecodeString(value)
	if err != nil {
		return NewPublicKey(), exception.ErrInvalidPublicKeyBytes(err)
	} else if n, err := v.SetBytes(buf[:]); err != nil {
		return NewPublicKey(), exception.ErrInvalidPublicKeyBytes(err)
	} else if n != len(buf) {
		return NewPublicKey(), exception.ErrInvalidPublicKeyBytes().WithDetailf("did not read enough bytes (expected %d, read %d)", len(buf), n)
	} else {
		return PublicKey{value: *v}, nil
	}
}

func NewPublicKeyFromBytes(value []byte) (PublicKey, error) {
	v := new(bls24317.G1Affine)

	if n, err := v.SetBytes(value); err != nil {
		return NewPublicKey(), exception.ErrInvalidPublicKeyBytes(err)
	} else if n != len(value) {
		return NewPublicKey(), exception.ErrInvalidPublicKeyBytes()
	} else {
		return PublicKey{value: *v}, nil
	}
}

func (p PublicKey) Value() bls24317.G1Affine {
	return p.value
}

func (p PublicKey) ToElement(ctx context.Context) fr.Element {
	ctx, span := tracer.Start(ctx, "ToElement")
	defer span.End()

	b := p.value.Bytes()
	r := elementPool.Get(ctx)
	defer elementPool.Put(ctx, r)
	r.SetBytes(b[:])
	return *r
}

func (p PublicKey) IsValid() bool {
	return !p.value.IsInfinity() && p.value.IsOnCurve() && p.value.IsInSubGroup()
}

func (pk PublicKey) Equals(other PublicKey) bool {
	return pk.value.Equal(&other.value)
}

func (pk PublicKey) Cmp(other PublicKey) int {
	return bytes.Compare(pk.Bytes(), other.Bytes())
}

func (pk PublicKey) Bytes() []byte {
	buf := pk.value.Bytes()
	return buf[:]
}

func (pk *PublicKey) SetBytes(data []byte) (*PublicKey, error) {
	if n, err := pk.value.SetBytes(data); err != nil {
		return nil, err
	} else if n != len(data) {
		return nil, exception.ErrInvalidPublicKeyBytes()
	}
	return pk, nil
}

func (pk *PublicKey) SetString(data string) (*PublicKey, error) {
	buf, err := encode.Base64.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return pk.SetBytes(buf)
}

func (pk PublicKey) String() string {
	buf := pk.value.Bytes()
	return encode.Base64.EncodeToString(buf[:])
}

func (pk PublicKey) Verify(ctx context.Context, message []byte, signature Signature) (bool, error) {
	_, span := tracer.Start(ctx, "Verify")
	defer span.End()

	if message == nil {
		return false, exception.ErrInvalidSignature().WithDetail("message cannot be nil")
	}
	if pk.value.IsInfinity() || !pk.value.IsInSubGroup() {
		return false, exception.ErrInvalidPublicKey().WithDetail("public key is infinity or not in the correct subgroup")
	}

	if signature.value.IsInfinity() || !signature.value.IsInSubGroup() {
		return false, exception.ErrInvalidSignature().WithDetail("signature is infinity or not in the correct subgroup")
	}

	p2, err := bls24317.EncodeToG2(message, []byte(signatureBasicDst))
	if err != nil {
		return false, err
	}

	lhs, err := bls24317.Pair(
		[]bls24317.G1Affine{pk.value},
		[]bls24317.G2Affine{p2},
	)
	if err != nil {
		return false, err
	}
	rhs, err := bls24317.Pair(
		[]bls24317.G1Affine{g1AffineGenerator},
		[]bls24317.G2Affine{signature.value},
	)
	if err != nil {
		return false, err
	}

	return lhs.Equal(&rhs), nil
}

// Combine secret keys into one aggregated key
func AggregateSecretKeys(ctx context.Context, secretKeys []SecretKey) (SecretKey, error) {
	if len(secretKeys) < 1 {
		return NewSecretKey(), fmt.Errorf("at least one public key is required")
	}
	result := elementPool.Get(ctx).SetZero()
	defer elementPool.Put(ctx, result)

	for _, k := range secretKeys {
		result.
			Add(result, &k.value)
	}
	return SecretKey{value: *result}, nil
}

// Combine public keys into one aggregated key
func AggregatePublicKeys(ctx context.Context, publicKeys ...PublicKey) (PublicKey, error) {
	ctx, span := tracer.Start(ctx, "AggregatePublicKeys")
	defer span.End()

	if len(publicKeys) < 1 {
		return NewPublicKey(), fmt.Errorf("at least one public key is required")
	}
	result := g1JacPool.Get(ctx)
	defer g1JacPool.Put(ctx, result)

	result.X.SetZero()
	result.Y.SetOne()
	result.Z.SetZero()

	for i, k := range publicKeys {
		if !k.value.IsInSubGroup() {
			return NewPublicKey(), fmt.Errorf("key at %d is not in the correct subgroup", i)
		} else if !k.value.IsOnCurve() {
			return NewPublicKey(), fmt.Errorf("key at %d is not on the correct curve", i)
		} else if k.value.IsInfinity() {
			return NewPublicKey(), fmt.Errorf("key at %d is the point at infinity", i)
		}
		result.AddMixed(&k.value)
	}

	g1 := g1AffinePool.Get(ctx)
	defer g1AffinePool.Put(ctx, g1)
	return PublicKey{value: *g1.FromJacobian(result)}, nil
}

// Combine signatures into one aggregated signature
func AggregateSignatures(ctx context.Context, signatures []Signature) (Signature, error) {
	ctx, span := tracer.Start(ctx, "AggregateSignatures")
	defer span.End()

	if len(signatures) < 1 {
		return NewSignature(), fmt.Errorf("at least one signature is required")
	}
	result := g2JacPool.Get(ctx)
	defer g2JacPool.Put(ctx, result)

	result.X.SetZero()
	result.Y.SetOne()
	result.Z.SetZero()

	for i, s := range signatures {
		// if s == nilSignature {
		// 	return nil, fmt.Errorf("signature at %d is nil, signature cannot be nil", i)
		// }
		if !s.value.IsInSubGroup() {
			return NewSignature(), fmt.Errorf("signature at %d is not in the correct subgroup", i)
		}
		result.AddMixed(&s.value)
	}

	g2 := g2AffinePool.Get(ctx)
	defer g2AffinePool.Put(ctx, g2)
	return Signature{value: *g2.FromJacobian(result)}, nil
}
