package gnark_test

import (
	gnark "Inskape/bls-shamir"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

type Actor struct {
	Secret *fr.Element
	Public *bls24317.G1Affine
}

func TestKeyExchange(t *testing.T) {
	psk := []byte("pre-shared-key")
	aliceSecretKey, err := gnark.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePublicKey := aliceSecretKey.PublicKey(context.TODO())

	alicePublicBytes := new(bls24317.G1Affine)
	_, err = alicePublicBytes.SetBytes(alicePublicKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	alice := Actor{
		Secret: new(fr.Element).SetBytes(aliceSecretKey.Bytes()),
		Public: alicePublicBytes,
	}

	bobSecretKey, err := gnark.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPublicKey := bobSecretKey.PublicKey(context.TODO())

	bobPublicBytes := new(bls24317.G1Affine)
	_, err = bobPublicBytes.SetBytes(bobPublicKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	bob := Actor{
		Secret: new(fr.Element).SetBytes(bobSecretKey.Bytes()),
		Public: bobPublicBytes,
	}

	l, err := new(bls24317.G1Affine).MultiExp([]bls24317.G1Affine{*bob.Public}, []fr.Element{*alice.Secret}, ecc.MultiExpConfig{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := new(bls24317.G1Affine).MultiExp([]bls24317.G1Affine{*alice.Public}, []fr.Element{*bob.Secret}, ecc.MultiExpConfig{})
	if err != nil {
		t.Fatal(err)
	}

	left := l.Bytes()
	right := r.Bytes()
	aliceSalt := hmac.New(gnark.NewBlake2bHash, psk).Sum(left[:])
	bobSalt := hmac.New(gnark.NewBlake2bHash, psk).Sum(right[:])
	t.Logf("alice l: %x salt: %x", left, aliceSalt)
	t.Logf("bob r: %x salt: %x", right, bobSalt)

	aliceReader := hkdf.New(gnark.NewBlake2bHash, left[:], aliceSalt, []byte("info"))
	aliceOutput := make([]byte, 256)
	aliceReader.Read(aliceOutput)
	bobReader := hkdf.New(gnark.NewBlake2bHash, right[:], bobSalt, []byte("info"))
	bobOutput := make([]byte, 256)
	bobReader.Read(bobOutput)

	t.Logf("alice key: %x", aliceOutput)
	t.Logf("bob key: %x", bobOutput)

	if !l.Equal(r) {
		t.Fatalf("%x != %x", l.Bytes(), r.Bytes())
	}

	if !bytes.Equal(aliceOutput, bobOutput) {
		t.Fatalf("alice key != bob key (%x != %x)", aliceOutput, bobOutput)
	}
}

func TestEncrypt(t *testing.T) {
	roundUUID := uuid.New()
	alice, err := gnark.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alicePK := alice.PublicKey(context.TODO())
	bob, err := gnark.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobPK := bob.PublicKey(context.TODO())
	charlie, err := gnark.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	charliePK := charlie.PublicKey(context.TODO())

	shares, _, err := gnark.Split(context.TODO(), alice, []gnark.PublicKey{alicePK, bobPK, charliePK}, 2)
	if err != nil {
		t.Fatal(err)
	}

	if share, ok := shares[bobPK]; ok {
		shareBytes := share.Bytes()
		b, err := alice.Encrypt(context.TODO(), shareBytes, bobPK, roundUUID)
		if err != nil {
			t.Fatal(err)
		}
		d, err := bob.Decrypt(context.TODO(), b, alicePK, roundUUID)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(shareBytes, d) {
			t.Fatalf("message does not equal decrypted bytes (%x != %x)", shareBytes, d)
		}
	} else {
		t.Fatal("no share found in split shares")
	}
}
