package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/google/uuid"
)

const (

	// Key type, EC or RSA.
	ktyEC  = "EC"
	ktyRSA = "RSA"

	// Use, Signature or Encryption
	useSIG = "sig"
	useENC = "enc"

	// P256 represents a 256-bit cryptographic elliptical curve type.
	P256 = "P-256"

	// P256K represents the Ethereum 256-bit cryptographic elliptical curve type.
	P256K = "P-256K"

	// P384 represents a 384-bit cryptographic elliptical curve type.
	P384 = "P-384"

	// P521 represents a 521-bit cryptographic elliptical curve type.
	P521 = "P-521"
)

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`

	// Elliptic curve, common to Public and Private keys
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	// RSA curve, common to Public and Private keys
	N string `json:"n"` // Modulus. Base64urlUInt-encoded
	E string `json:"e"` // Exponent. Base64urlUInt-encoded

	// For Private Keys, both Elliptic and RSA
	D string `json:"d"`
}

func NewEthereum() (*JWK, error) {

	nativeKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwkKey := &JWK{}
	jwkKey.Kid = uuid.New().String()
	jwkKey.Kty = ktyEC
	jwkKey.Crv = P256K
	jwkKey.Alg = "ES256K" // ECDSA using P256K and SHA-256
	jwkKey.Use = useSIG
	jwkKey.D = toBase64url(nativeKey.D.Bytes())
	jwkKey.X = toBase64url(nativeKey.X.Bytes())
	jwkKey.Y = toBase64url(nativeKey.Y.Bytes())

	return jwkKey, nil

}

func NewECDSA() (*JWK, error) {

	nativeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	jwkKey := &JWK{}
	jwkKey.Kid = uuid.New().String()
	jwkKey.Kty = ktyEC
	jwkKey.Crv = P256
	jwkKey.Alg = "ES256" // ECDSA using P-256 and SHA-256
	jwkKey.Use = useSIG
	jwkKey.D = toBase64url(nativeKey.D.Bytes())
	jwkKey.X = toBase64url(nativeKey.X.Bytes())
	jwkKey.Y = toBase64url(nativeKey.Y.Bytes())

	return jwkKey, nil

}

func NewJWKFromFile(location string) (*JWK, error) {

	// Read the key from the file as a text string
	keyData, err := ioutil.ReadFile(location)
	if err != nil {
		return nil, err
	}

	// Convert to a JWK structure
	j := &JWK{}
	err = json.Unmarshal(keyData, j)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func NewFromBytes(b []byte) (k *JWK, err error) {

	// Convert to a JWK structure
	k = &JWK{}
	err = json.Unmarshal(b, k)
	if err != nil {
		return nil, err
	}

	return k, nil
}

func (k *JWK) AsJSON() ([]byte, error) {
	return json.Marshal(k)
}

func (key *JWK) GetKid() string {
	return key.Kid
}

func (key *JWK) GetAlg() string {
	return key.Alg
}

func (k *JWK) String() (s string) {
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func (key *JWK) PublicJWKKey() (publicKey *JWK) {

	// Create a new JWK struct
	publicKey = &JWK{}

	// Copy the relevant fields for a public key
	publicKey.Kid = key.Kid
	publicKey.Kty = key.Kty
	publicKey.Use = key.Use
	publicKey.Alg = key.Alg
	publicKey.Crv = key.Crv
	publicKey.X = key.X
	publicKey.Y = key.Y
	publicKey.N = key.N
	publicKey.E = key.E

	return publicKey
}

func (key *JWK) GetPublicKey() (publicKeyEC crypto.PublicKey, err error) {

	if key.X == "" || key.Y == "" || key.Crv == "" {
		return nil, fmt.Errorf("Missing fields in the JWK")
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	xCoordinate, err := fromBase64url(key.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := fromBase64url(key.Y)
	if err != nil {
		return nil, err
	}

	publicKey := &ecdsa.PublicKey{}
	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	publicKey.X = big.NewInt(0).SetBytes(xCoordinate)
	publicKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	switch key.Crv {
	case P256:
		publicKey.Curve = elliptic.P256()
	case P384:
		publicKey.Curve = elliptic.P384()
	case P521:
		publicKey.Curve = elliptic.P521()
	}

	return publicKey, nil
}

func (key *JWK) GetPrivateKey() (privateKeyEC crypto.PrivateKey, err error) {

	if key.X == "" || key.Y == "" || key.D == "" || key.Crv == "" {
		return nil, fmt.Errorf("Missing fields in the JWK")
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	xCoordinate, err := fromBase64url(key.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := fromBase64url(key.Y)
	if err != nil {
		return nil, err
	}

	privateKey := &ecdsa.PrivateKey{}
	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	privateKey.X = big.NewInt(0).SetBytes(xCoordinate)
	privateKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	switch key.Crv {
	case P256:
		privateKey.Curve = elliptic.P256()
	case P384:
		privateKey.Curve = elliptic.P384()
	case P521:
		privateKey.Curve = elliptic.P521()
	}

	var dCoordinate []byte
	if len(key.D) > 0 {
		dCoordinate, err = fromBase64url(key.D)
		if err != nil {
			return nil, err
		}
		privateKey.D = big.NewInt(0).SetBytes(dCoordinate)
	}

	return privateKey, nil

}

func LoadECPublicKeyFromJWKFile(location string) crypto.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}

	j := JWK{}
	json.Unmarshal(keyData, &j)

	key, e := JWK2PublicECDSA(j)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func LoadECPrivateKeyFromJWKFile(location string) crypto.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}

	j := JWK{}
	json.Unmarshal(keyData, &j)

	key, e := JWK2PrivateECDSA(j)
	if e != nil {
		panic(e.Error())
	}
	return key
}

// JWK2PublicECDSA parses a jsonWebKey and turns it into an ECDSA public key.
func JWK2PublicECDSA(j JWK) (publicKey *ecdsa.PublicKey, err error) {
	if j.X == "" || j.Y == "" || j.Crv == "" {
		return nil, fmt.Errorf("Missing fields in the JWK")
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	xCoordinate, err := fromBase64url(j.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := fromBase64url(j.Y)
	if err != nil {
		return nil, err
	}

	publicKey = &ecdsa.PublicKey{}
	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	publicKey.X = big.NewInt(0).SetBytes(xCoordinate)
	publicKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	switch j.Crv {
	case P256:
		publicKey.Curve = elliptic.P256()
	case P384:
		publicKey.Curve = elliptic.P384()
	case P521:
		publicKey.Curve = elliptic.P521()
	}

	return

}

// JWK2PrivateECDSA parses a jsonWebKey and turns it into an ECDSA private key.
func JWK2PrivateECDSA(j JWK) (privateKey *ecdsa.PrivateKey, err error) {
	if j.X == "" || j.Y == "" || j.D == "" || j.Crv == "" {
		return nil, fmt.Errorf("Missing fields in the JWK")
	}

	// Decode the X coordinate from Base64.
	//
	// According to RFC 7518, this is a Base64 URL unsigned integer.
	// https://tools.ietf.org/html/rfc7518#section-6.3
	xCoordinate, err := fromBase64url(j.X)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := fromBase64url(j.Y)
	if err != nil {
		return nil, err
	}

	privateKey = &ecdsa.PrivateKey{}
	// Turn the X coordinate into *big.Int.
	//
	// According to RFC 7517, these numbers are in big-endian format.
	// https://tools.ietf.org/html/rfc7517#appendix-A.1
	privateKey.X = big.NewInt(0).SetBytes(xCoordinate)
	privateKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	switch j.Crv {
	case P256:
		privateKey.Curve = elliptic.P256()
	case P384:
		privateKey.Curve = elliptic.P384()
	case P521:
		privateKey.Curve = elliptic.P521()
	}

	var dCoordinate []byte
	if len(j.D) > 0 {
		dCoordinate, err = fromBase64url(j.D)
		if err != nil {
			return nil, err
		}
		privateKey.D = big.NewInt(0).SetBytes(dCoordinate)
	}

	return privateKey, nil

}

// fromBase64url removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func fromBase64url(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

func toBase64url(n []byte) string {
	return base64.RawURLEncoding.EncodeToString(n)
}

// base64urlTrailingPadding removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func base64urlTrailingPadding(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
