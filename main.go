package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"log"
)

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096) //2048
	return privkey, &privkey.PublicKey
}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {

	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {

	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)
	return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("key type is not RSA")
}

func main() {

	privKey, pubKey := GenerateRsaKeyPair()
	fmt.Println("PrivateKey:", privKey)
	pkey := ExportRsaPrivateKeyAsPemStr(privKey)

	//fmt.Println("Key-1:", pkey)
	fmt.Println("-----------------")

	pkey2, err := ParseRsaPrivateKeyFromPemStr(pkey)
	fmt.Println(err, "Key-2:", pkey2)

	pubKeystr, _ := ExportRsaPublicKeyAsPemStr(pubKey)

	pubKey2, err := ParseRsaPublicKeyFromPemStr(pubKeystr)

	fmt.Println("PublicKey:", pubKeystr, err)

	fmt.Println(pubKey, err)
	fmt.Println("*************************")
	fmt.Println(pubKey2)

}

func encrypt(publicKey *rsa.PublicKey, sourceText, label []byte) (encryptedText []byte) {
	var err error
	var md5_hash hash.Hash
	md5_hash = md5.New()
	if encryptedText, err = rsa.EncryptOAEP(md5_hash, rand.Reader, publicKey, sourceText, label); err != nil {
		log.Fatal(err)
	}
	return
}

func decrypt(privateKey *rsa.PrivateKey, encryptedText, label []byte) (decryptedText []byte) {
	var err error
	var md5_hash hash.Hash
	md5_hash = md5.New()
	if decryptedText, err = rsa.DecryptOAEP(md5_hash, rand.Reader, privateKey, encryptedText, label); err != nil {
		log.Fatal(err)
	}
	return
}
