package tir

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	common "github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/google/uuid"
	lestrrat "github.com/lestrrat-go/jwx/jwk"

	v4 "github.com/golang-jwt/jwt/v4"
	ldprocessor "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/signature/suite"
	"github.com/hyperledger/aries-framework-go/component/models/signature/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ld "github.com/piprate/json-gold/ld"
)

/**
 * Global file accessor
 */
var localFileAccessor fileAccessor = diskFileAccessor{}

var ErrorTokenProviderNoKey = errors.New("no_key_configured")
var ErrorTokenProviderNoVC = errors.New("no_vc_configured")
var ErrorTokenProviderNoVerificationMethod = errors.New("no_verification_method_configured")
var ErrorBadPrivateKey = errors.New("bad_private_key_length")
var ErrorTokenProviderNoDid = errors.New("no_did_configured")

type TokenProvider interface {
	GetToken(vc *verifiable.Credential, audience string) (string, error)
	GetAuthCredential() (vc *verifiable.Credential, err error)
}

type M2MTokenProvider struct {
	// encodes the token according to the configuration
	tokenEncoder TokenEncoder
	// the credential
	authCredential *verifiable.Credential
	// Signer for the Verifiable Presentation
	signer util.Signer
	// clock to get issuance time from
	clock common.Clock
	// verification method to be used on the tokens
	verificationMethod string
	// did of the token provider
	did string
}

type TokenEncoder interface {
	GetEncodedToken(vp *verifiable.Presentation, audience string) (encodedToken string, err error)
}

type Base64TokenEncoder struct{}

func InitM2MTokenProvider(config *configModel.Configuration, clock common.Clock) (tokenProvider TokenProvider, err error) {
	m2mConfig := config.M2M

	if m2mConfig.KeyPath == "" {
		logging.Log().Warn("No private key configured, cannot provide m2m tokens.")
		return tokenProvider, ErrorTokenProviderNoKey
	}
	if m2mConfig.VerificationMethod == "" {
		logging.Log().Warn("No verification method configured, cannot provide m2m tokens.")
		return tokenProvider, ErrorTokenProviderNoVerificationMethod
	}

	privateKey, err := getSigningKey(m2mConfig.KeyPath)
	if err != nil {
		logging.Log().Warnf("Was not able to load the signing key. Err: %v", err)
		return tokenProvider, err
	}
	jwkHolder, err := lestrrat.New(privateKey)
	if err != nil {
		logging.Log().Infof("Was not able to load private key to jwk. Err: %v", err)
		return tokenProvider, err
	}
	keyBytes, err := json.Marshal(jwkHolder)
	if err != nil {
		logging.Log().Warnf("Was not able to marshal the key. Err: %v", err)
		return tokenProvider, err
	}

	var theKey jwk.JWK

	theKey.UnmarshalJSON(keyBytes)
	signer, err := util.GetSigner(&theKey)
	if err != nil {
		logging.Log().Warnf("Was not able to create the token signer. Err: %v", err)
		return tokenProvider, err
	}

	if m2mConfig.CredentialPath == "" {
		return tokenProvider, ErrorTokenProviderNoVC
	}
	if config.Verifier.Did == "" {
		logging.Log().Warn("No did for token provider")
		return tokenProvider, ErrorTokenProviderNoDid
	}

	vc, err := getCredential(m2mConfig.CredentialPath)
	if err != nil {
		logging.Log().Warnf("Was not able to load the credential. Err: %v", err)
		return tokenProvider, err
	}

	return M2MTokenProvider{tokenEncoder: Base64TokenEncoder{}, authCredential: vc, signer: signer, did: config.Verifier.Did, clock: clock, verificationMethod: m2mConfig.VerificationMethod}, err
}

func (tokenProvider M2MTokenProvider) GetAuthCredential() (vc *verifiable.Credential, err error) {
	logging.Log().Info("Get cred")
	return tokenProvider.authCredential, err
}

func (tokenProvider M2MTokenProvider) GetToken(vc *verifiable.Credential, audience string) (token string, err error) {

	vp, err := tokenProvider.signVerifiablePresentation(vc)
	if err != nil {
		logging.Log().Warnf("Was not able to get a signed verifiable presentation. Err: %v", err)
		return token, err
	}
	return tokenProvider.tokenEncoder.GetEncodedToken(vp, audience)
}

func (base64TokenEncoder Base64TokenEncoder) GetEncodedToken(vc *verifiable.Presentation, audience string) (encodedToken string, err error) {

	marshalledPayload, err := vc.MarshalJSON()
	if err != nil {
		logging.Log().Warnf("Was not able to marshal the token payload. Err: %v", err)
		return encodedToken, err
	}

	return base64.RawURLEncoding.EncodeToString(marshalledPayload), err
}

func (tp M2MTokenProvider) signVerifiablePresentation(authCredential *verifiable.Credential) (vp *verifiable.Presentation, err error) {
	vp, err = verifiable.NewPresentation(verifiable.WithCredentials(authCredential))
	if err != nil {
		logging.Log().Warnf("Was not able to create a presentation. Err: %v", err)
		return vp, err
	}
	vp.ID = "urn:uuid:" + uuid.NewString()
	vp.Holder = tp.did

	created := tp.clock.Now()
	err = vp.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		Created:                 &created,
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(tp.signer)),
		SignatureRepresentation: verifiable.SignatureJWS,
		VerificationMethod:      tp.verificationMethod,
	}, ldprocessor.WithDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient)))

	if err != nil {
		logging.Log().Warnf("Was not able to add an ld-proof. Err: %v", err)
		return vp, err
	}

	return vp, err
}

/**
* Read siging key from local filesystem
 */
func getSigningKey(keyPath string) (key *rsa.PrivateKey, err error) {
	// read key file
	rawKey, err := localFileAccessor.ReadFile(keyPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the key file from %s. err: %v", keyPath, err)
		return key, err
	} // parse key file
	key, err = v4.ParseRSAPrivateKeyFromPEM(rawKey)
	if err != nil {
		logging.Log().Warnf("Was not able to parse the key %s. err: %v", rawKey, err)
		return key, err
	}

	return
}

func getCredential(vcPath string) (vc *verifiable.Credential, err error) {
	vcBytes, err := localFileAccessor.ReadFile(vcPath)
	if err != nil {
		logging.Log().Warnf("Was not able to read the vc file from %s. err: %v", vcPath, err)
		return vc, err
	}

	return verifiable.ParseCredential(vcBytes)
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
