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
	"os"
	"time"
)

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 2048) //4096,2048,1024 time increases as you increase number of bits
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

	startingTime := time.Now()

	privKey, pubKey := GenerateRsaKeyPair()
	fmt.Println("PrivateKey:", privKey)
	pkey := ExportRsaPrivateKeyAsPemStr(privKey)

	privKey.Precompute()
	err := privKey.Validate()
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

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

	var label []byte
	sourceText := []byte(`I Love my country`)
	encryptedText := encrypt(pubKey, sourceText, label)
	fmt.Println("encryptedText:", encryptedText)

	fmt.Println("#################")
	fmt.Println("sourceText...:", sourceText)
	decryptedText := decrypt(pkey2, encryptedText, label)
	fmt.Println("decryptedText:", decryptedText)

	fmt.Println("TimeTaken:", time.Since(startingTime).Milliseconds(), " ms")

}

func encrypt(publicKey *rsa.PublicKey, sourceText, label []byte) (encryptedText []byte) {
	var err error
	var md5_hash hash.Hash = md5.New()
	//md5_hash = md5.New()
	if encryptedText, err = rsa.EncryptOAEP(md5_hash, rand.Reader, publicKey, sourceText, label); err != nil {
		log.Fatal(err)
	}
	return
}

func decrypt(privateKey *rsa.PrivateKey, encryptedText, label []byte) (decryptedText []byte) {
	var err error
	var md5_hash hash.Hash = md5.New()
	//md5_hash = md5.New()
	if decryptedText, err = rsa.DecryptOAEP(md5_hash, rand.Reader, privateKey, encryptedText, label); err != nil {
		log.Fatal(err)
	}
	return
}
