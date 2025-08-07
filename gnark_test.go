package gnark_test

import (
	gnark "Inskape/bls-shamir"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
)

const (
	numNodes  int    = 10
	threshold uint32 = uint32((numNodes/3)*2 + 1)
	keySeed   string = "drive oh set leak trail palm neutral school popular remedy inflate tile curriculum grip makeup excitement presidential plaintiff donor role useful miracle dilemma car"
	keyBase64 string = "DJTi-6e5K6Fpwm7LUgg7PVusfyUfSgJP1OYGDvAXR28"
)

var (
	nodes   = make([]gnark.SecretKey, numNodes)
	pubKeys = make([]gnark.PublicKey, numNodes)
)

func TestMain(m *testing.M) {
	var err error
	for i := 0; i < numNodes; i++ {
		var ikm [48]byte
		rand.Read(ikm[:])
		nodes[i], err = gnark.GenerateKeyWithSeed(ikm[:])
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		pubKeys[i] = nodes[i].PublicKey(context.TODO())
	}
	os.Exit(m.Run())
}

func TestGenerateKey(t *testing.T) {
	sk, err := gnark.GenerateKeyWithSeed([]byte(keySeed))
	if err != nil {
		t.Error(err)
	}
	if sk.String() != keyBase64 {
		t.Errorf("incorrect secret key from seed (wanted %s, got %s)", keyBase64, sk)
	}
	t.Logf("%s == %s", sk, keyBase64)
}

func TestSign(t *testing.T) {
	msg := "Hello World"
	sk, err := gnark.GenerateKeyWithSeed([]byte(keySeed))
	if err != nil {
		t.Error(err)
	}
	t.Logf("original secret: %s", sk)
	sig, err := sk.Sign(context.TODO(), []byte(msg))
	if err != nil {
		t.Error(err)
	}
	pk := sk.PublicKey(context.TODO())
	ok, err := pk.Verify(context.TODO(), []byte(msg), sig)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("invalid signature")
	}
}

func TestShamirSecret(t *testing.T) {
	msg := []byte("hello world")
	sk, err := gnark.GenerateKeyWithSeed([]byte(keySeed))
	if err != nil {
		t.Error(err)
	}
	pk := sk.PublicKey(context.TODO())
	t.Logf("original secret: %s", sk)
	shares, publicPoly, err := gnark.Split(context.TODO(), sk, pubKeys, threshold)
	if err != nil {
		t.Error(err)
		return
	}
	partialShares := make(map[gnark.PublicKey]gnark.SecretKey, threshold)
	for key, share := range shares {
		if uint32(len(partialShares)) > threshold {
			break
		}
		r := gnark.EvaluatePolynomialG1(context.TODO(), key.ToElement(context.TODO()), publicPoly)
		pubKey := share.PublicKey(context.TODO())
		otherKey := pubKey.Value()
		if !r.Equal(&otherKey) {
			t.Errorf("evaluated public key cannot verify with result")
		}
		partialShares[key] = share
	}
	recovered, err := gnark.RecoverSecretKey(context.TODO(), partialShares)
	if err != nil {
		t.Error(err)
	}
	t.Logf("recovered secret: %s", recovered)
	if !sk.Equals(recovered) {
		t.Errorf("shamir secret key recovery failed")
	}
	publicKeys := make(map[gnark.PublicKey]gnark.PublicKey)
	i := 0
	for publicKey, share := range shares {
		if uint32(i) >= threshold {
			break
		}
		pubKey := share.PublicKey(context.TODO())
		sig, err := share.Sign(context.TODO(), msg)
		if err != nil {
			t.Error(err)
		}
		if ok, err := pubKey.Verify(context.TODO(), msg, sig); err != nil {
			t.Error(err)
		} else if !ok {
			t.Errorf("invalid signature for share %s", publicKey)
		}
		publicKeys[publicKey] = pubKey
		i++
	}
	recoveredPublicKey, err := gnark.RecoverPublicKey(context.TODO(), publicKeys)
	if err != nil {
		t.Error(err)
	}
	t.Logf("original public: %s", pk)
	t.Logf("recovered public: %s", recoveredPublicKey)
	if !pk.Equals(*recoveredPublicKey) {
		t.Error("shamir public key recovery failed")
	}
}

func TestShamirSignature(t *testing.T) {
	msg := "Hello World"
	sk, err := gnark.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	shares, publicPoly, err := gnark.Split(context.TODO(), sk, pubKeys, threshold)
	if err != nil {
		t.Error(err)
	}
	count := uint32(0)
	signatures := make(map[gnark.PublicKey]gnark.Signature)
	for shareholder, share := range shares {
		if count >= threshold {
			break
		}

		signature, err := share.Sign(context.TODO(), []byte(msg))
		if err != nil {
			t.Error(err)
		}

		pk := share.PublicKey(context.TODO())

		if r := gnark.EvaluatePolynomialG1(context.TODO(), shareholder.ToElement(context.TODO()), publicPoly); !pk.Equals(gnark.NewPublicKeyFromG1(r)) {
			t.Error("evaluated public key != expected public key")
		}

		if ok, err := pk.Verify(context.TODO(), []byte(msg), signature); err != nil {
			t.Error(err)
		} else if ok {
			signatures[shareholder] = signature
		} else {
			t.Error(err)
		}
	}
	publicKeys := make(map[gnark.PublicKey]gnark.PublicKey)
	for shareholder, share := range shares {
		publicKeys[shareholder] = share.PublicKey(context.TODO())
	}

	originalSignature, err := sk.Sign(context.TODO(), []byte(msg))
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("original signature: %s", originalSignature)
	}

	thresholdSignature, err := gnark.RecoverSignature(context.TODO(), signatures)
	if err != nil {
		t.Error(err)
	}
	t.Logf("threshold signature: %s", thresholdSignature)

	if !thresholdSignature.Equals(originalSignature) {
		t.Error("threshold signature does not match original signature")
	}

	thresholdPublicKey, err := gnark.RecoverPublicKey(context.TODO(), publicKeys)
	if err != nil {
		t.Error(err)
	}
	pk := sk.PublicKey(context.TODO())
	if !pk.Equals(*thresholdPublicKey) {
		t.Errorf("incorrect threshold public key calculated (%s != %s)", pk, thresholdPublicKey)
	}

	ok, err := thresholdPublicKey.Verify(context.TODO(), []byte(msg), thresholdSignature)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("threshold public key cannot verify threshold signature")
	}
}

func TestAggregatedSignature(t *testing.T) {
	// struct to hold shares and the public polynomial
	type Member struct {
		id                 gnark.PublicKey
		secret             gnark.SecretKey
		ownShares          map[gnark.PublicKey]gnark.SecretKey
		publicPoly         []bls24317.G1Affine
		aggregatePoly      []bls24317.G1Affine
		otherShares        map[gnark.PublicKey]gnark.SecretKey
		otherPolynomials   [][]bls24317.G1Affine
		secretShare        gnark.SecretKey
		thresholdPublicKey gnark.PublicKey
	}

	// Generate shares for each node
	members := make([]Member, len(nodes))
	for i, node := range nodes {
		shares, publicCoefficients, err := gnark.Split(context.TODO(), node, pubKeys, threshold)
		if err != nil {
			t.Error(err)
			return
		}
		e := gnark.NewPublicKeyFromG1(gnark.EvaluatePolynomialG1(context.TODO(), pubKeys[i].ToElement(context.TODO()), publicCoefficients))
		pk := shares[pubKeys[i]].PublicKey(context.TODO())
		if !e.Equals(pk) {
			t.Error("evaluated public key does not equal share public key")
			return
		}
		members[i] = Member{
			id:               pubKeys[i],
			secret:           node,
			ownShares:        shares,
			publicPoly:       publicCoefficients,
			aggregatePoly:    publicCoefficients,
			otherShares:      make(map[gnark.PublicKey]gnark.SecretKey, len(nodes)-1),
			otherPolynomials: make([][]bls24317.G1Affine, 0, len(nodes)-1),
		}
	}

	// Calculate aggregate secret key and public key for verification downstream
	groupSK, err := gnark.AggregateSecretKeys(context.TODO(), nodes)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("group secret key: %s", groupSK)
	groupPK, err := gnark.AggregatePublicKeys(context.TODO(), pubKeys...)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("group public key: %s", groupPK)
	groupSig, err := groupSK.Sign(context.TODO(), groupPK.Bytes())
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("group signature: %s", groupSig)
	if ok, err := groupPK.Verify(context.TODO(), groupPK.Bytes(), groupSig); err != nil {
		t.Error(err)
		return
	} else if !ok {
		t.Error("invalid group signature calculated")
		return
	}

	// Distribute shares and public polynomial to the corresponding nodes
	for i := 0; i < len(members); i++ {
		for j := i + 1; j < len(members); j++ {
			members[i].otherPolynomials = append(members[i].otherPolynomials, members[j].publicPoly)
			members[j].otherPolynomials = append(members[j].otherPolynomials, members[i].publicPoly)
			members[i].otherShares[members[j].id] = members[j].ownShares[members[i].id]
			members[j].otherShares[members[i].id] = members[i].ownShares[members[j].id]
		}
	}

	// User Shamir interpolation to find the aggregate public key on the public polynomial
	// publicKeys := make(map[gnark.PublicKey]gnark.PublicKey, threshold)
	for i, member := range members {
		// Start with a copy of the base polynomial
		thresholdPoly := make([]bls24317.G1Affine, 0, len(member.publicPoly))
		thresholdPoly = append(thresholdPoly, member.publicPoly...)
		// Sum all of the public polynomials
		for _, otherPoly := range member.otherPolynomials {
			if len(thresholdPoly) != len(otherPoly) {
				t.Error("cannot add polynomials of different degrees")
			}
			for i, coefficient := range otherPoly {
				thresholdPoly[i].Add(&thresholdPoly[i], &coefficient)
			}
		}
		members[i].aggregatePoly = thresholdPoly
		p := gnark.EvaluatePolynomialG1(context.TODO(), *new(fr.Element).SetZero(), thresholdPoly)
		members[i].thresholdPublicKey = gnark.NewPublicKeyFromG1(p)
		if !members[i].thresholdPublicKey.Equals(groupPK) {
			t.Errorf("calculated threshold key does not equal original threshold key (local threshold key: %s, threshold key: %s)", members[i].thresholdPublicKey, groupPK)
		}

		// Each node aggregates it's received shares (along with it's share of it's own secret)
		values := make([]gnark.SecretKey, 0, len(members))
		values = append(values, member.ownShares[member.id])
		for _, sk := range member.otherShares {
			values = append(values, sk)
		}
		share, err := gnark.AggregateSecretKeys(context.TODO(), values)
		if err != nil {
			t.Error(err)
		}
		members[i].secretShare = share
		t.Logf("secret: %s, public: %s, threshold: %s", share, share.PublicKey(context.TODO()), groupPK)
	}

	// Each node signs and verifies the same message with their aggregated share
	signatures := make(map[gnark.PublicKey]gnark.Signature, threshold)
	for i, member := range members {
		signature, err := member.secretShare.Sign(context.TODO(), member.thresholdPublicKey.Bytes())
		if err != nil {
			t.Error(err)
			return
		}
		pk := member.secretShare.PublicKey(context.TODO())
		if ok, err := pk.Verify(context.TODO(), member.thresholdPublicKey.Bytes(), signature); err != nil {
			t.Error(err)
			return
		} else if !ok {
			t.Error("invalid signature for share")
		} else {
			signatures[member.id] = signature
		}

		// Exit for loop if we have reached a threshold of nodes
		if uint32(i) >= threshold {
			break
		}
	}

	// Use Shamir interpolation to find the aggregated signature
	thresholdSignature, err := gnark.RecoverSignature(context.TODO(), signatures)
	if err != nil {
		t.Error(err)
		return
	}
	t.Logf("signature: %s", thresholdSignature)

	// Validate the aggregated signature with the aggregated public key
	ok, err := groupPK.Verify(context.TODO(), groupPK.Bytes(), thresholdSignature)
	if err != nil {
		t.Error(err)
	} else if !ok {
		t.Error("threshold signature cannot be verified by threshold public key")
	} else {
		t.Log("threshold signature is valid")
	}
}
