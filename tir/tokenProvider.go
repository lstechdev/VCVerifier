package tir

import (
	"crypto/rsa"
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
	GetSignedToken(payload []map[string]interface{}, audience string) ([]byte, error)
	GetAuthCredential() (vc []map[string]interface{}, err error)
}

type M2MTokenProvider struct {
	// did of the token provider - needed?
	issuerDid string
	// key to be used for signing jwt's
	signingKey jwk.Key
	// token signer to be used
	tokenSigner common.TokenSigner
	// the credential
	authCredential []map[string]interface{}
	// time provider
	clock common.Clock
}

func InitM2MTokenProvider(config *configModel.Configuration, clock common.Clock) (tokenProvider TokenProvider, err error) {
	m2mConfig := config.M2M

	if m2mConfig.KeyPath == "" {
		return tokenProvider, ErrorTokenProviderNoKey
	}
	if m2mConfig.CredentialPath == "" {
		return tokenProvider, ErrorTokenProviderNoVC
	}

	var signingKey jwk.RSAPrivateKey
	rawKey, err := getSigningKey(config.M2M.KeyPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the signing key. E: %s", err)
		return tokenProvider, err
	}
	err = signingKey.FromRaw(rawKey)
	if err != nil {
		logging.Log().Warnf("Was not able to read the raw key. E: %s", err)
		return tokenProvider, err

	}
	if config.Verifier.Did == "" {
		logging.Log().Warn("No did configured for the verifier.")
		return tokenProvider, err
	}
	vc, err := getCredential(m2mConfig.CredentialPath)
	if err != nil {
		logging.Log().Warnf("Was not able to load the credential. Err: %v", err)
		return tokenProvider, err
	}
	return M2MTokenProvider{issuerDid: config.Verifier.Did, signingKey: signingKey, tokenSigner: common.JwtTokenSigner{}, authCredential: vc, clock: common.RealClock{}}, err

}

func (tokenProvider M2MTokenProvider) GetAuthCredential() (vc []map[string]interface{}, err error) {
	return tokenProvider.authCredential, err
}

func (tokenProvider M2MTokenProvider) GetSignedToken(payload []map[string]interface{}, audience string) (signedToken []byte, err error) {
	now := tokenProvider.clock.Now()
	jwtBuilder := jwt.NewBuilder().Issuer(tokenProvider.issuerDid).Audience([]string{audience}).IssuedAt(now).Claim("kid", tokenProvider.signingKey.KeyID()).Expiration(now.Add(time.Minute*30)).Claim("vp", payload)
	unsignedToken, err := jwtBuilder.Build()
	if err != nil {
		logging.Log().Warnf("Was not able to build the token. E: %s", err)
		return signedToken, err
	}
	// use the same signing algorithm like for the i4trust tokens
	return tokenProvider.tokenSigner.Sign(unsignedToken, jwa.ES256, tokenProvider.signingKey)
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
