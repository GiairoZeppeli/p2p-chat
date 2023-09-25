package crypt

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"github.com/libp2p/go-libp2p/core/crypto"
	"io"
	"log"

	"github.com/cloudflare/redoctober/padding"
	"github.com/cloudflare/redoctober/symcrypt"
)

var Curve = elliptic.P256

func GeneratePrivateKey(r io.Reader) crypto.PrivKey {
	privateKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, r)
	if err != nil {
		log.Fatal(err)
	}
	return privateKey
}

func Encrypt(public *ecdsa.PublicKey, ephemeral *ecdsa.PrivateKey, in []byte) (out []byte, err error) {
	x, _ := public.Curve.ScalarMult(public.X, public.Y, ephemeral.D.Bytes())
	if x == nil {
		return nil, errors.New("Не удалось сгенерировать ключ шифрования")
	}
	sharedSecret := sha256.Sum256(x.Bytes())

	initVector, err := symcrypt.MakeRandom(16)
	if err != nil {
		return
	}

	paddedData := padding.AddPadding(in)

	cypherText, err := symcrypt.EncryptCBC(paddedData, initVector, sharedSecret[:16])
	if err != nil {
		return
	}

	ephPub := elliptic.Marshal(public.Curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)
	out = make([]byte, 1+len(ephPub)+16)
	out[0] = byte(len(ephPub))
	copy(out[1:], ephPub)
	copy(out[1+len(ephPub):], initVector)
	out = append(out, cypherText...)

	h := hmac.New(sha1.New, sharedSecret[16:])
	h.Write(initVector)
	h.Write(cypherText)
	out = h.Sum(out)
	return
}

func Decrypt(private *ecdsa.PrivateKey, in []byte) (out []byte, err error) {
	ephLen := int(in[0])
	ephPub := in[1 : 1+ephLen]
	cypherText := in[1+ephLen:]

	if len(cypherText) < (sha1.Size + aes.BlockSize) {
		return nil, errors.New("Неправильный зашифрованный текст")
	}

	x, y := elliptic.Unmarshal(Curve(), ephPub)

	ok := Curve().IsOnCurve(x, y)
	if x == nil || !ok {
		return nil, errors.New("Неправильный публичный ключ")
	}

	x, _ = private.Curve.ScalarMult(x, y, private.D.Bytes())
	if x == nil {
		return nil, errors.New("Не удалось сгенерировать ключ шифрования")
	}

	sharedSecret := sha256.Sum256(x.Bytes())

	hmacIndexStart := len(cypherText) - sha1.Size

	h := hmac.New(sha1.New, sharedSecret[16:])
	h.Write(cypherText[:hmacIndexStart])
	mac := h.Sum(nil)
	if !hmac.Equal(mac, cypherText[hmacIndexStart:]) {
		return nil, errors.New("Неправильный MAC")
	}

	decryptedPaddedData, err := symcrypt.DecryptCBC(cypherText[aes.BlockSize:hmacIndexStart], cypherText[:aes.BlockSize], sharedSecret[:16])
	if err != nil {
		return
	}
	out, err = padding.RemovePadding(decryptedPaddedData)
	return
}
