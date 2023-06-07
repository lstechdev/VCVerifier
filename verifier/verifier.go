package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/tir"

	logging "github.com/fiware/VCVerifier/logging"

	client "github.com/fiware/dsba-pdp/http"

	"github.com/fiware/VCVerifier/ssikit"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/patrickmn/go-cache"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/valyala/fasttemplate"
)

var ErrorNoDID = errors.New("no_did_configured")
var ErrorNoTIR = errors.New("no_tir_configured")
var ErrorInvalidVC = errors.New("invalid_vc")
var ErrorNoSuchSession = errors.New("no_such_session")
var ErrorWrongGrantType = errors.New("wrong_grant_type")
var ErrorNoSuchCode = errors.New("no_such_code")
var ErrorRedirectUriMismatch = errors.New("redirect_uri_does_not_match")
var ErrorVerficationContextSetup = errors.New("no_valid_verification_context")

// Actual implementation of the verfifier functionality

// verifier interface
type Verifier interface {
	ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string) (qr string, err error)
	StartSiopFlow(host string, protocol string, callback string, sessionId string, clientId string) (connectionString string, err error)
	StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string) (authenticationRequest string, err error)
	GetToken(grantType string, authorizationCode string, redirectUri string) (jwtString string, expiration int64, err error)
	GetJWKS() jwk.Set
	AuthenticationResponse(state string, verifiableCredentials []map[string]interface{}, holder string) (sameDevice SameDeviceResponse, err error)
}

type VerificationService interface {
	// Verifies the given VC. FIXME Currently a positiv result is returned even when no policy was checked
	VerifyVC(verifiableCredential VerifiableCredential, verificationContext VerificationContext) (result bool, err error)
}

// implementation of the verifier, using waltId ssikit and gaia-x compliance issuers registry as a validation backends.
type CredentialVerifier struct {
	// did of the verifier
	did string
	// trusted-issuers-registry to be used for verification
	tirAddress string
	// key to sign the jwt's with
	signingKey jwk.Key
	// cache to be used for in-progress authentication sessions
	sessionCache Cache
	// cache to be used for jwt retrieval
	tokenCache Cache
	// nonce generator
	nonceGenerator NonceGenerator
	// provides the current time
	clock Clock
	// provides the capabilities to signt the jwt
	tokenSigner TokenSigner
	// provide the configuration to be used with the credentials
	credentialsConfig CredentialsConfig
	// Verification services to be used on the credentials
	verificationServices []VerificationService
}

// allow singleton access to the verifier
var verifier Verifier

// http client to be used
var httpClient = client.HttpClient()

// interfaces and default implementations

type Clock interface {
	Now() time.Time
}

type VerificationContext interface{}

type TrustRegistriesVerificationContext struct {
	trustedIssuersLists           []string
	trustedParticipantsRegistries []string
}

func (trvc TrustRegistriesVerificationContext) GetTrustedIssuersLists() []string {
	return trvc.trustedIssuersLists
}

func (trvc TrustRegistriesVerificationContext) GetTrustedParticipantLists() []string {
	return trvc.trustedParticipantsRegistries
}

type realClock struct{}

func (realClock) Now() time.Time {
	return time.Now()
}

type TokenSigner interface {
	Sign(t jwt.Token, alg jwa.SignatureAlgorithm, key interface{}, options ...jwt.SignOption) ([]byte, error)
}

type jwtTokenSigner struct{}

func (jwtTokenSigner) Sign(t jwt.Token, alg jwa.SignatureAlgorithm, key interface{}, options ...jwt.SignOption) ([]byte, error) {
	return jwt.Sign(t, alg, key, options...)
}

type randomGenerator struct{}

type NonceGenerator interface {
	GenerateNonce() string
}

// generate a random nonce
func (r *randomGenerator) GenerateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}

// struct to represent a running login session
type loginSession struct {
	// is it using the same-device flow?
	sameDevice bool
	// callback to be notfied after success
	callback string
	// sessionId to be included in the notification
	sessionId string
	// clientId provided for the session
	clientId string
}

// struct to represent a token, accessible through the token endpoint
type tokenStore struct {
	token        jwt.Token
	redirect_uri string
}

// Response structure for successful same-device authentications
type SameDeviceResponse struct {
	// the redirect target to be informed
	RedirectTarget string
	// code of the siop flow
	Code string
	// session id provided by the client
	SessionId string
}

/**
* Global singelton access to the verifier
**/
func GetVerifier() Verifier {
	if verifier == nil {
		logging.Log().Error("Verifier is not initialized.")
	}
	return verifier
}

/**
* Initialize the verifier and all its components from the configuration
**/
func InitVerifier(verifierConfig *configModel.Verifier, repoConfig *configModel.ConfigRepo, ssiKitClient ssikit.SSIKit) (err error) {

	err = verifyConfig(verifierConfig)
	if err != nil {
		return
	}

	sessionCache := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)
	tokenCache := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)

	externalSsiKitVerifier, err := InitSsiKitExternalVerificationService(verifierConfig, ssiKitClient)
	if err != nil {
		logging.Log().Errorf("Was not able to initiate a external verifier. Err: %v", err)
		return err
	}
	externalGaiaXVerifier := InitGaiaXRegistryVerificationService(verifierConfig)

	credentialsConfig, err := InitServiceBackedCredentialsConfig(repoConfig)
	if err != nil {
		logging.Log().Errorf("Was not able to initiate the credentials config. Err: %v", err)
	}

	tirClient, err := tir.NewTirHttpClient()
	if err != nil {
		logging.Log().Errorf("Was not able to instantiate the trusted-issuers-registry client. Err: %v", err)
		return err
	}
	trustedParticipantVerificationService := TrustedParticipantVerificationService{tirClient: tirClient}
	trustedIssuerVerificationService := TrustedIssuerVerificationService{tirClient: tirClient}

	key, err := initPrivateKey()

	if err != nil {
		logging.Log().Errorf("Was not able to initiate a signing key. Err: %v", err)
		return err
	}
	logging.Log().Warnf("Initiated key %s.", logging.PrettyPrintObject(key))
	verifier = &CredentialVerifier{
		verifierConfig.Did,
		verifierConfig.TirAddress,
		key,
		sessionCache,
		tokenCache,
		&randomGenerator{},
		realClock{},
		jwtTokenSigner{},
		credentialsConfig,
		[]VerificationService{
			&externalSsiKitVerifier,
			&externalGaiaXVerifier,
			&trustedParticipantVerificationService,
			&trustedIssuerVerificationService,
		},
	}

	logging.Log().Debug("Successfully initalized the verifier")
	return
}

/**
*   Initializes the cross-device login flow and returns all neccessary information as a qr-code
**/
func (v *CredentialVerifier) ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string) (qr string, err error) {

	logging.Log().Debugf("Generate a login qr for %s.", callback)
	authenticationRequest, err := v.initSiopFlow(host, protocol, callback, sessionId, clientId)

	if err != nil {
		return qr, err
	}

	png, err := qrcode.Encode(authenticationRequest, qrcode.Medium, 256)
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	return base64Img, err
}

/**
* Starts a siop-flow and returns the required connection information
**/
func (v *CredentialVerifier) StartSiopFlow(host string, protocol string, callback string, sessionId string, clientId string) (connectionString string, err error) {
	logging.Log().Debugf("Start a plain siop-flow fro %s.", callback)

	return v.initSiopFlow(host, protocol, callback, sessionId, clientId)
}

/**
* Starts a same-device siop-flow and returns the required redirection information
**/
func (v *CredentialVerifier) StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string) (authenticationRequest string, err error) {
	logging.Log().Debugf("Initiate samedevice flow for %s.", host)
	state := v.nonceGenerator.GenerateNonce()

	loginSession := loginSession{true, fmt.Sprintf("%s://%s%s", protocol, host, redirectPath), sessionId, clientId}
	err = v.sessionCache.Add(state, loginSession, cache.DefaultExpiration)
	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache. Err: %v", logging.PrettyPrintObject(loginSession), err)
		return authenticationRequest, err
	}

	redirectUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)

	walletUri := protocol + "://" + host + redirectPath
	return v.createAuthenticationRequest(walletUri, redirectUri, state, clientId), err
}

/**
*   Returns an already generated jwt from the cache to properly authorized requests. Every token will only be returend once.
**/
func (v *CredentialVerifier) GetToken(grantType string, authorizationCode string, redirectUri string) (jwtString string, expiration int64, err error) {

	if grantType != "authorization_code" {
		return jwtString, expiration, ErrorWrongGrantType
	}

	tokenSessionInterface, hit := v.tokenCache.Get(authorizationCode)
	if !hit {
		logging.Log().Infof("No such authorization code cached: %s.", authorizationCode)
		return jwtString, expiration, ErrorNoSuchCode
	}
	// we do only allow retrieval once.
	v.tokenCache.Delete(authorizationCode)

	tokenSession := tokenSessionInterface.(tokenStore)
	if tokenSession.redirect_uri != redirectUri {
		logging.Log().Infof("Redirect uri does not match for authorization %s. Was %s but is expected %s.", authorizationCode, redirectUri, tokenSession.redirect_uri)
		return jwtString, expiration, ErrorRedirectUriMismatch
	}
	jwtBytes, err := v.tokenSigner.Sign(tokenSession.token, jwa.ES256, v.signingKey)
	if err != nil {
		logging.Log().Warnf("Was not able to sign the token. Err: %v", err)
		return jwtString, expiration, err
	}
	expiration = tokenSession.token.Expiration().Unix() - v.clock.Now().Unix()

	return string(jwtBytes), expiration, err
}

/**
* Return the JWKS used by the verifier to allow jwt verification
**/
func (v *CredentialVerifier) GetJWKS() jwk.Set {
	jwks := jwk.NewSet()
	publicKey, _ := v.signingKey.PublicKey()
	jwks.Add(publicKey)
	return jwks
}

/**
* Receive credentials and verify them in the context of an already present login-session. Will return either an error if failed, a sameDevice response to be used for
* redirection or notify the original initiator(in case of a cross-device flow)
**/
func (v *CredentialVerifier) AuthenticationResponse(state string, verifiableCredentials []map[string]interface{}, holder string) (sameDevice SameDeviceResponse, err error) {

	logging.Log().Debugf("Authenticate credential for session %s", state)

	loginSessionInterface, hit := v.sessionCache.Get(state)
	if !hit {
		logging.Log().Infof("Session %s is either expired or did never exist.", state)
		return sameDevice, ErrorNoSuchSession
	}
	loginSession := loginSessionInterface.(loginSession)

	mappedCredentials := []VerifiableCredential{}
	for _, vc := range verifiableCredentials {
		mappedCredential, err := MapVerifiableCredential(vc)
		if err != nil {
			logging.Log().Warnf("Failed to map credential %s. Err: %v", logging.PrettyPrintObject(vc), err)
			return sameDevice, err
		}
		mappedCredentials = append(mappedCredentials, mappedCredential)
	}

	// TODO extract into separate policy
	trustedChain, _ := verifyChain(mappedCredentials)

	for _, mappedCredential := range mappedCredentials {
		verificationContext, err := v.getTrustRegistriesVerificationContext(loginSession.clientId, mappedCredential.Types)
		if err != nil {
			logging.Log().Warnf("Was not able to create a valid verification context. Credential will be rejected. Err: %v", err)
			return sameDevice, ErrorVerficationContextSetup
		}
		//FIXME make it an error if no policy was checked at all( possible misconfiguration)
		for _, verificationService := range v.verificationServices {
			if trustedChain {
				logging.Log().Debug("Credentials chain is trusted.")
				_, isTrustedParticipantVerificationService := verificationService.(*TrustedParticipantVerificationService)
				_, isTrustedIssuerVerificationService := verificationService.(*TrustedIssuerVerificationService)
				if isTrustedIssuerVerificationService || isTrustedParticipantVerificationService {
					logging.Log().Debug("Skip the tir services.")
					continue
				}
			}

			result, err := verificationService.VerifyVC(mappedCredential, verificationContext)
			if err != nil {
				logging.Log().Warnf("Failed to verify credential %s. Err: %v", logging.PrettyPrintObject(mappedCredential), err)
				return sameDevice, err
			}
			if !result {
				logging.Log().Infof("VC %s is not valid.", logging.PrettyPrintObject(mappedCredential))
				return sameDevice, ErrorInvalidVC
			}
		}
	}

	// we ignore the error here, since the only consequence is that sub will be empty.
	hostname, _ := getHostName(loginSession.callback)

	token, err := v.generateJWT(verifiableCredentials, holder, hostname)
	if err != nil {
		logging.Log().Warnf("Was not able to create a jwt for %s. Err: %v", state, err)
		return sameDevice, err
	}

	tokenStore := tokenStore{token, loginSession.callback}
	authorizationCode := v.nonceGenerator.GenerateNonce()
	// store for retrieval by token endpoint
	err = v.tokenCache.Add(authorizationCode, tokenStore, cache.DefaultExpiration)
	logging.Log().Infof("Stored token for %s.", authorizationCode)
	if err != nil {
		logging.Log().Warnf("Was not able to store the token %s in cache.", logging.PrettyPrintObject(tokenStore))
		return sameDevice, err
	}
	if loginSession.sameDevice {
		return SameDeviceResponse{loginSession.callback, authorizationCode, loginSession.sessionId}, err
	} else {
		return sameDevice, callbackToRequestor(loginSession, authorizationCode)
	}
}

func (v *CredentialVerifier) getTrustRegistriesVerificationContext(clientId string, credentialTypes []string) (verificationContext TrustRegistriesVerificationContext, err error) {
	trustedIssuersLists := []string{}
	trustedParticipantsRegistries := []string{}

	for _, credentialType := range credentialTypes {
		issuersLists, err := v.credentialsConfig.GetTrustedIssuersLists(clientId, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid trusted-issuers-lists for client %s and type %s. Err: %v", clientId, credentialType, err)
			return verificationContext, err
		}
		participantsLists, err := v.credentialsConfig.GetTrustedParticipantLists(clientId, credentialType)
		if err != nil {
			logging.Log().Warnf("Was not able to get valid trusted-pariticpants-registries for client %s and type %s. Err: %v", clientId, credentialType, err)
			return verificationContext, err
		}
		trustedIssuersLists = append(trustedIssuersLists, issuersLists...)
		trustedParticipantsRegistries = append(trustedParticipantsRegistries, participantsLists...)
	}
	context := TrustRegistriesVerificationContext{trustedIssuersLists: trustedIssuersLists, trustedParticipantsRegistries: trustedParticipantsRegistries}
	return context, err
}

// TODO Use more generic approach to validate that every credential is issued by a party that we trust
func verifyChain(vcs []VerifiableCredential) (bool, error) {
	if len(vcs) != 3 {
		// TODO Simplification to be removed/replaced
		return false, nil
	}

	var legalEntity VerifiableCredential
	var naturalEntity VerifiableCredential
	var compliance VerifiableCredential

	for _, vc := range vcs {
		if vc.GetCredentialType() == "gx:LegalParticipant" {
			legalEntity = vc
		}
		if vc.GetCredentialType() == "gx:compliance" {
			compliance = vc
		}
		if vc.GetCredentialType() == "gx:NaturalParticipant" {
			naturalEntity = vc
		}
	}

	// Make sure that the compliance credential is issued for the given credential
	if legalEntity.CredentialSubject.Id != compliance.CredentialSubject.Id {
		return false, fmt.Errorf("compliance credential was not issued for the presented legal entity. Compliance VC subject id %s, legal VC id %s", compliance.CredentialSubject.Id, legalEntity.Id)
	}
	// Natural participientVC must be issued by the legal participient VC
	if legalEntity.CredentialSubject.Id != naturalEntity.Issuer {
		return false, fmt.Errorf("natural participent credential was not issued by the presented legal entity. Legal Participant VC id %s, natural VC issuer %s", legalEntity.CredentialSubject.Id, naturalEntity.Issuer)
	}
	return true, nil
}

// initializes the cross-device siop flow
func (v *CredentialVerifier) initSiopFlow(host string, protocol string, callback string, sessionId string, clientId string) (authenticationRequest string, err error) {
	state := v.nonceGenerator.GenerateNonce()

	loginSession := loginSession{false, callback, sessionId, clientId}
	err = v.sessionCache.Add(state, loginSession, cache.DefaultExpiration)

	if err != nil {
		logging.Log().Warnf("Was not able to store the login session %s in cache.", logging.PrettyPrintObject(loginSession))
		return authenticationRequest, err
	}
	redirectUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)
	authenticationRequest = v.createAuthenticationRequest("openid://", redirectUri, state, clientId)

	logging.Log().Debugf("Authentication request is %s.", authenticationRequest)
	return authenticationRequest, err
}

// generate a jwt, containing the credential and mandatory information as defined by the dsba-convergence
func (v *CredentialVerifier) generateJWT(verifiableCredentials []map[string]interface{}, holder string, audience string) (generatedJwt jwt.Token, err error) {

	jwtBuilder := jwt.NewBuilder().Issuer(v.did).Claim("client_id", v.did).Subject(holder).Audience([]string{audience}).Claim("kid", v.signingKey.KeyID()).Expiration(v.clock.Now().Add(time.Minute * 30))

	if len(verifiableCredentials) > 1 {
		jwtBuilder.Claim("verifiablePresentation", verifiableCredentials)
	} else {
		jwtBuilder.Claim("verifiableCredential", verifiableCredentials[0])
	}

	token, err := jwtBuilder.Build()
	if err != nil {
		logging.Log().Warnf("Was not able to build a token. Err: %v", err)
		return generatedJwt, err
	}

	return token, err
}

// creates an authenticationRequest string from the given parameters
func (v *CredentialVerifier) createAuthenticationRequest(base string, redirect_uri string, state string, clientId string) string {

	// We use a template to generate the final string
	template := "{{base}}?response_type=vp_token" +
		"&response_mode=direct_post" +
		"&client_id={{client_id}}" +
		"&redirect_uri={{redirect_uri}}" +
		"&state={{state}}" +
		"&nonce={{nonce}}"

	var scope string
	if clientId != "" {
		typesToBeRequested, err := v.credentialsConfig.GetScope(clientId)
		if err != nil {
			logging.Log().Warnf("Was not able to get the scope to be requested for client %s. Err: %v", clientId, err)
		} else {
			template = template + "&scope={{scope}}"
			scope = strings.Join(typesToBeRequested, ",")
		}
	}

	t := fasttemplate.New(template, "{{", "}}")
	authRequest := t.ExecuteString(map[string]interface{}{
		"base":         base,
		"scope":        scope,
		"client_id":    v.did,
		"redirect_uri": redirect_uri,
		"state":        state,
		"nonce":        v.nonceGenerator.GenerateNonce(),
	})

	return authRequest

}

// call back to the original initiator of the login-session, providing an authorization_code for token retrieval
func callbackToRequestor(loginSession loginSession, authorizationCode string) error {
	callbackRequest, err := http.NewRequest("GET", loginSession.callback, nil)
	logging.Log().Infof("Try to callback %s", loginSession.callback)
	if err != nil {
		logging.Log().Warnf("Was not able to create callback request to %s. Err: %v", loginSession.callback, err)
		return err
	}
	q := callbackRequest.URL.Query()
	q.Add("state", loginSession.sessionId)
	q.Add("code", authorizationCode)
	callbackRequest.URL.RawQuery = q.Encode()

	_, err = httpClient.Do(callbackRequest)
	if err != nil {
		logging.Log().Warnf("Was not able to notify requestor %s. Err: %v", loginSession.callback, err)
		return err
	}
	return nil
}

// helper method to extract the hostname from a url
func getHostName(urlString string) (host string, err error) {
	url, err := url.Parse(urlString)
	if err != nil {
		logging.Log().Warnf("Was not able to extract the host from the redirect_url %s. Err: %v", urlString, err)
		return host, err
	}
	return url.Host, err
}

// Initialize the private key of the verifier. Might need to be persisted in future iterations.
func initPrivateKey() (key jwk.Key, err error) {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, err
	}
	key, err = jwk.New(newKey)
	if err != nil {
		return nil, err
	}
	if err != jwk.AssignKeyID(key) {
		return nil, err
	}
	return key, err
}

// verify the configuration
func verifyConfig(verifierConfig *configModel.Verifier) error {
	if verifierConfig.Did == "" {
		return ErrorNoDID
	}
	if verifierConfig.TirAddress == "" {
		return ErrorNoTIR
	}
	return nil
}
