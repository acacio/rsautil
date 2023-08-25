package rsautil

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"testing"
)

func TestGenKey(t *testing.T) {
	priv, pub, err := GenerateKeyPair(Bits2048)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}
	ascpriv := string(PrivateKeyBytes(priv))
	fmt.Printf("Private key:\n%s\n", ascpriv)

	ascpub, err := PublicKeyBytes(pub)
	if err != nil {
		t.Errorf("Failed to encode public key: %v", err)
	}
	fmt.Printf("Public key:\n%s\n", string(ascpub))
}

func TestKeyRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeyPair(Bits2048)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}
	ascpriv := PrivateKeyBytes(priv)
	//fmt.Printf("Private key:\n%s\n", string(ascpriv))

	newpriv, err := BytesToPrivateKey(ascpriv)
	if err != nil {
		t.Errorf("Failed parsing exported key: %v", err)
	}

	if !newpriv.Equal(priv) {
		t.Errorf("Failed to recreate original private key")
	}

	newpub := newpriv.Public().(*rsa.PublicKey)
	if !newpub.Equal(pub) {
		t.Errorf("Failed to recreate original private key")
	}
}

func TestDataRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeyPair(Bits2048)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}

	data := make([]byte, 32, 32)
	rand.Read(data)
	encrypted, err := EncryptWithPublicKey(data, pub)
	if err != nil {
		t.Errorf("Failed encrypting data: %v", err)
	}

	recovered, err := DecryptWithPrivateKey(encrypted, priv)
	if err != nil {
		t.Errorf("Failed decrypting data: %v", err)
	}

	if !bytes.Equal(data, recovered) {
		t.Errorf("Data roundtrip failed: %v", err)
	}
}

func TestSign(t *testing.T) {
	priv, _, err := GenerateKeyPair(Bits2048)
	if err != nil {
		t.Errorf("Failed to generate key: %v", err)
	}

	ascpriv := string(PrivateKeyBytes(priv))
	fmt.Printf("Private key:\n%s\n", ascpriv)
	data := make([]byte, 512, 512)
	rand.Read(data)
	text := base64.StdEncoding.EncodeToString(data)

	signed, err := Sign([]byte(text), priv)
	if err != nil {
		t.Errorf("Failed to sign data: %v", err)
	}
	log.Printf("Signed data:\n%s\n", base64.StdEncoding.EncodeToString(signed))
}
