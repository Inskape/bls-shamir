package gnark

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"hash"

	"github.com/consensys/gnark-crypto/ecc"
	bls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	"github.com/google/uuid"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

const (
	keySize = 32
)

var (
	salt = []byte("HMAC_Key_Exchange_Salt")
)

// returns a new hash.Hash computing the BLAKE2b-512 checksum
func NewBlake2bHash() hash.Hash {
	h, err := blake2b.New512(salt)
	if err != nil {
		panic(err)
	}
	return h
}

func keyExchange(ctx context.Context, secret fr.Element, peerKey bls24317.G1Affine, uuid uuid.UUID) ([]byte, error) {
	_, span := tracer.Start(ctx, "KeyExchange")
	defer span.End()

	UUID, err := uuid.MarshalBinary()
	if err != nil {
		return nil, err
	}

	sharedKey, err := new(bls24317.G1Affine).MultiExp([]bls24317.G1Affine{peerKey}, []fr.Element{secret}, ecc.MultiExpConfig{})
	if err != nil {
		return nil, err
	}
	b := sharedKey.Bytes()

	salt := hmac.New(NewBlake2bHash, UUID).Sum(b[:])

	reader := hkdf.New(sha512.New, b[:], salt, UUID)
	output := make([]byte, keySize)
	reader.Read(output)
	return output, nil
}

func (k SecretKey) Encrypt(ctx context.Context, data []byte, peerKey PublicKey, roundUUID uuid.UUID) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "Encrypt")
	defer span.End()

	sharedSecret, err := keyExchange(ctx, k.value, peerKey.value, roundUUID)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}

	//Make the cipher text a byte array of size BlockSize + the length of the message
	cipherText := make([]byte, aes.BlockSize+len(data))

	iv := cipherText[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], data)

	return cipherText, nil
}

func (k SecretKey) Decrypt(ctx context.Context, data []byte, peerKey PublicKey, roundUUID uuid.UUID) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "Decrypt")
	defer span.End()

	sharedSecret, err := keyExchange(ctx, k.value, peerKey.value, roundUUID)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("encrypted date block size is too short")
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}
