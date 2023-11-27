package tir

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"time"

	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	v4 "github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

/**
 * Global file accessor
 */
var localFileAccessor fileAccessor = diskFileAccessor{}

var ErrorTokenProviderNoKey = errors.New("no_key_configured")
var ErrorTokenProviderNoVC = errors.New("no_vc_configured")

type TokenProvider interface {
	GetToken(payload []map[string]interface{}, audience string) ([]byte, error)
	GetAuthCredential() (vc []map[string]interface{}, err error)
}

type M2MTokenProvider struct {
	// encodes the token according to the configuration
	tokenEncoder TokenEncoder
	// the credential
	authCredential []map[string]interface{}
}

type TokenEncoder interface {
	GetEncodedToken(payload []map[string]interface{}, audience string) (encodedToken []byte, err error)
}

type Base64TokenEncoder struct{}

type JWTTokenEncoder struct {
	// key to be used for signing jwt's
	signingKey jwk.Key
	// token signer to be used
	tokenSigner common.TokenSigner
	// time provider
	clock common.Clock
	// did of the token provider
	issuerDid string
}

func InitM2MTokenProvider(config *configModel.Configuration, clock common.Clock) (tokenProvider TokenProvider, err error) {
	m2mConfig := config.M2M

	var tokenEncoder TokenEncoder
	if m2mConfig.KeyPath != "" {
		tokenEncoder, err = InitJWTTokenEncoder(m2mConfig.KeyPath, config.Verifier.Did)
	} else {
		tokenEncoder = Base64TokenEncoder{}
	}
	if err != nil {
		logging.Log().Warnf("Was not able to create the token encoder. Err: %v", err)
	}

	if m2mConfig.CredentialPath == "" {
		return tokenProvider, ErrorTokenProviderNoVC
	}

	vc, err := getCredential(m2mConfig.CredentialPath)
	if err != nil {
		logging.Log().Warnf("Was not able to load the credential. Err: %v", err)
		return tokenProvider, err
	}
	return M2MTokenProvider{tokenEncoder: tokenEncoder, authCredential: vc}, err
}

func InitJWTTokenEncoder(keyPath string, issuerDid string) (tokenEncoder TokenEncoder, err error) {
	if issuerDid == "" {
		logging.Log().Warn("No did configured for the verifier.")
		return tokenEncoder, err
	}
	var signingKey jwk.RSAPrivateKey
	rawKey, err := getSigningKey(keyPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the signing key. E: %s", err)
		return tokenEncoder, err
	}
	err = signingKey.FromRaw(rawKey)
	if err != nil {
		logging.Log().Warnf("Was not able to read the raw key. E: %s", err)
		return tokenEncoder, err

	}
	return JWTTokenEncoder{signingKey: signingKey, tokenSigner: common.JwtTokenSigner{}, clock: common.RealClock{}, issuerDid: issuerDid}, err
}

func (tokenProvider M2MTokenProvider) GetAuthCredential() (vc []map[string]interface{}, err error) {
	return tokenProvider.authCredential, err
}

func (tokenProvider M2MTokenProvider) GetToken(payload []map[string]interface{}, audience string) (token []byte, err error) {
	return tokenProvider.tokenEncoder.GetEncodedToken(payload, audience)
}

func (base64TokenEncoder Base64TokenEncoder) GetEncodedToken(payload []map[string]interface{}, audience string) (encodedToken []byte, err error) {
	marshalledPayload, err := json.Marshal(payload)
	if err != nil {
		logging.Log().Warnf("Was not able to marshal the token payload. Err: %v")
		return encodedToken, err
	}
	base64.RawURLEncoding.Encode(encodedToken, marshalledPayload)
	return encodedToken, err
}

func (jwtTokenEncoder JWTTokenEncoder) GetEncodedToken(payload []map[string]interface{}, audience string) (encodedToken []byte, err error) {
	now := jwtTokenEncoder.clock.Now()
	jwtBuilder := jwt.NewBuilder().Issuer(jwtTokenEncoder.issuerDid).Audience([]string{jwtTokenEncoder.audience}).IssuedAt(now).Claim("kid", jwtTokenEncoder.signingKey.KeyID()).Expiration(now.Add(time.Minute*30)).Claim("vp", payload)
	unsignedToken, err := jwtBuilder.Build()
	if err != nil {
		logging.Log().Warnf("Was not able to build the token. E: %s", err)
		return encodedToken, err
	}
	// use the same signing algorithm like for the i4trust tokens
	return jwtTokenEncoder.tokenSigner.Sign(unsignedToken, jwa.ES256, jwtTokenEncoder.signingKey)
}

/**
* Read siging key from local filesystem
 */
func getSigningKey(keyPath string) (key *rsa.PrivateKey, err error) {
	// read key file
	priv, err := localFileAccessor.ReadFile(keyPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the key file from %s. err: %v", keyPath, err)
		return key, err
	}

	// parse key file
	key, err = v4.ParseRSAPrivateKeyFromPEM(priv)
	if err != nil {
		logging.Log().Warnf("Was not able to parse the key %s. err: %v", priv, err)
		return key, err
	}

	return
}

func getCredential(vcPath string) (vc []map[string]interface{}, err error) {
	vcBytes, err := localFileAccessor.ReadFile(vcPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the vc file from %s. err: %v", vcPath, err)
		return vc, err
	}

	err = json.Unmarshal(vcBytes, &vc)
	if err != nil {
		logging.Log().Warnf("Was not able to unmarshal the vc. Err: %v", err)
		return vc, err
	}
	return vc, err
}

// file system interfaces

// Interface to the http-client
type fileAccessor interface {
	ReadFile(filename string) ([]byte, error)
}
type diskFileAccessor struct{}

func (diskFileAccessor) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}
