package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
	configModel "wistefan/VCVerifier/config"

	logging "wistefan/VCVerifier/logging"

	client "github.com/fiware/dsba-pdp/http"

	"wistefan/VCVerifier/ssikit"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/patrickmn/go-cache"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/valyala/fasttemplate"
)

// Actual implementation of the verfifier functionality

// struct to represent the verifier
type Verifier struct {
	// did of the verifier
	did string
	// trusted-issuers-registry to be used for verification
	tirAddress string
	// optional scope of credentials to be requested
	scope string
	// array of policies to be verified - currently statically filled on init
	policies []ssikit.Policy
	// key to sign the jwt's with
	signingKey *jwk.Key
	// client for connection waltId
	ssiKitClient *ssikit.SSIKitClient
	// cache to be used for in-progress authentication sessions
	sessionCache *cache.Cache
	// cache to be used for jwt retrieval
	tokenCache *cache.Cache
}

// allow singleton access to the verifier
var verifier *Verifier

/**
* Initialize the verifier and all its components from the configuration
**/
func InitVerifier(verifierConfig *configModel.Verifier, ssiKitClient *ssikit.SSIKitClient) (err error) {

	err = verifyConfig(verifierConfig)
	if err != nil {
		return
	}

	sessionCache := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)
	tokenCache := cache.New(time.Duration(verifierConfig.SessionExpiry)*time.Second, time.Duration(2*verifierConfig.SessionExpiry)*time.Second)

	policies := []ssikit.Policy{
		{Policy: "SignaturePolicy"},
		{Policy: "IssuedDateBeforePolicy"},
		{Policy: "ValidFromBeforePolicy"},
		{Policy: "ExpirationDateAfterPolicy"},
		{Policy: "TrustedIssuerRegistryPolicy", Argument: &ssikit.TirArgument{RegistryAddress: verifierConfig.TirAddress}},
	}

	key, err := initPrivateKey()
	if err != nil {
		logging.Log().Errorf("Was not able to initiate a signing key. Err: %v", err)
		return err
	}
	verifier = &Verifier{verifierConfig.Did, verifierConfig.TirAddress, verifierConfig.RequestScope, policies, &key, ssiKitClient, sessionCache, tokenCache}

	logging.Log().Debug("Successfully initalized the verifier")
	return
}

// Initialize the private key of the verifier. Might need to be persisted in future iterations.
func initPrivateKey() (key jwk.Key, err error) {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return jwk.New(newKey)
}

// verify the configuration
func verifyConfig(verifierConfig *configModel.Verifier) error {
	if verifierConfig.Did == "" {
		return errors.New("no_did_configured")
	}
	if verifierConfig.TirAddress == "" {
		return errors.New("no_tir_configured")
	}
	return nil
}

/**
* Global singelton access to the verifier
**/
func GetVerifier() *Verifier {
	return verifier
}

// struct to represent a running login session
type loginSession struct {
	// is it using the same-device flow?
	sameDevice bool
	// callback to be notfied after success
	callback string
	// sessionId to be included in the notification
	sessionId string
}

// struct to represent a token, accessible through the token endpoint
type tokenStore struct {
	token        jwt.Token
	redirect_uri string
}

/**
*   Initializes the cross-device login flow and returns all neccessary information as a qr-code
**/
func (v *Verifier) ReturnLoginQR(host string, protocol string, callback string, sessionId string) (qr string, err error) {

	logging.Log().Debugf("Generate a login qr for %s.", callback)
	authenticationRequest := v.initSiopFlow(host, protocol, callback, sessionId)

	png, err := qrcode.Encode(authenticationRequest, qrcode.Medium, 256)
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	return base64Img, err
}

// initializes the cross-device siop flow
func (v *Verifier) initSiopFlow(host string, protocol string, callback string, sessionId string) string {
	state := generateNonce()

	v.sessionCache.Add(state, loginSession{false, callback, sessionId}, cache.DefaultExpiration)

	redirectUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)
	authenticationRequest := v.createAuthenticationRequest("openid://", redirectUri, state)

	logging.Log().Debugf("Authentication request is %s.", authenticationRequest)
	return authenticationRequest
}

/**
* Starts a siop-flow and returns the required connection information
**/
func (v *Verifier) StartSiopFlow(host string, protocol string, callback string, sessionId string) (connectionString string) {
	logging.Log().Debugf("Start a plain siop-flow fro %s.", callback)

	return v.initSiopFlow(host, protocol, callback, sessionId)
}

/**
* Starts a same-device siop-flow and returns the required redirection information
**/
func (v *Verifier) StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string) string {
	logging.Log().Debugf("Initiate samedevice flow for %s.", host)
	state := generateNonce()

	v.sessionCache.Add(state, loginSession{true, "", sessionId}, cache.DefaultExpiration)

	redirectUri := fmt.Sprintf("%s://%s/api/v1/authentication_response", protocol, host)

	walletUri := protocol + "://" + host + redirectPath
	return v.createAuthenticationRequest(walletUri, redirectUri, state)
}

/**
*   Returns an already generated jwt from the cache to properly authorized requests. Every token will only be returend once.
**/
func (v *Verifier) GetToken(grantType string, authorizationCode string, redirectUri string) (jwtString string, expiration int64, err error) {

	if grantType != "authorization_code" {
		return jwtString, expiration, errors.New("wrong_grant_type")
	}

	tokenSessionInterface, hit := v.tokenCache.Get(authorizationCode)
	if !hit {
		logging.Log().Infof("No such authorization code cached: %s.", authorizationCode)
		return jwtString, expiration, errors.New("no_such_code")
	}
	// we do only allow retrieval once.
	v.tokenCache.Delete(authorizationCode)

	tokenSession := tokenSessionInterface.(tokenStore)
	if tokenSession.redirect_uri != redirectUri {
		logging.Log().Infof("Redirect uri does not match for authorization %s. Was %s but is expected %s.", authorizationCode, redirectUri, tokenSession.redirect_uri)
		return jwtString, expiration, errors.New("redirect_uri_does_not_match")
	}

	signingAlgorithm, err := getAlgorithm((*v.signingKey).Algorithm())
	if err != nil {
		return jwtString, expiration, err
	}

	jwtBytes, err := jwt.Sign(tokenSession.token, signingAlgorithm, *v.signingKey)
	if err != nil {
		logging.Log().Warnf("Was not able to sign the token. Err: %v", err)
		return jwtString, expiration, err
	}
	expiration = tokenSession.token.Expiration().Unix() - time.Now().Unix()

	return string(jwtBytes), expiration, err
}

/**
* Return the JWKS used by the verifier to allow jwt verification
**/
func (v *Verifier) GetJWKS() jwk.Set {
	jwks := jwk.NewSet()
	jwks.Add(*v.signingKey)
	return jwks
}

// Response structure for successfull same-device authentications
type SameDeviceResponse struct {
	// the redirect target to be informed
	RedirectTarget string
	// code of the siop flow
	Code string
	// session id provided by the client
	SessionId string
}

/**
* Receive credentials and verify them in the context of an already present login-session. Will return either an error if failed, a sameDevice response to be used for
* redirection or notify the original initiator(in case of a cross-device flow)
**/
func (v *Verifier) AuthenticationResponse(state string, verifiableCredentials []map[string]interface{}, holder string) (sameDevice SameDeviceResponse, err error) {

	logging.Log().Debug("Authenticate credential for session %s", state)

	loginSessionInterface, hit := v.sessionCache.Get(state)
	if !hit {
		logging.Log().Infof("Session %s is either expired or did never exist.", state)
		return sameDevice, errors.New("no_such_session")
	}
	loginSession := loginSessionInterface.(loginSession)

	for _, vc := range verifiableCredentials {
		result, err := v.ssiKitClient.VerifyVC(v.policies, vc)
		if err != nil {
			logging.Log().Warnf("Failed to verify credential %s. Err: %v", logging.PrettyPrintObject(vc), err)
			return sameDevice, err
		}
		if !result {
			logging.Log().Infof("VC %s is not valid.", logging.PrettyPrintObject(vc))
			return sameDevice, errors.New("invalid_vc")
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
	authorizationCode := generateNonce()
	// store for retrieval by token endpoint
	v.tokenCache.Add(authorizationCode, tokenStore, cache.DefaultExpiration)

	if loginSession.sameDevice {
		return SameDeviceResponse{loginSession.callback, authorizationCode, state}, err
	} else {
		return sameDevice, callbackToRequestor(loginSession, authorizationCode)
	}
}

// call back to the original initiator of the login-session, providing an authorization_code for token retrieval
func callbackToRequestor(loginSession loginSession, authorizationCode string) error {
	callbackRequest, err := http.NewRequest("GET", loginSession.callback, nil)
	if err != nil {
		logging.Log().Warnf("Was not able to create callback request to %s. Err: %v", loginSession.callback, err)
		return err
	}
	q := callbackRequest.URL.Query()
	q.Add("state", loginSession.sessionId)
	q.Add("code", authorizationCode)
	callbackRequest.URL.RawQuery = q.Encode()

	_, err = client.HttpClient().Do(callbackRequest)
	if err != nil {
		logging.Log().Warnf("Was not able to notify requestor %s. Err: %v", loginSession.callback, err)
	}
	return err
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

// generate a jwt, containing the credential and mandatory information as defined by the dsba-convergence
func (v *Verifier) generateJWT(verifiableCredentials []map[string]interface{}, holder string, audience string) (generatedJwt jwt.Token, err error) {
	credentialString, err := json.Marshal(verifiableCredentials[0])
	if err != nil {
		logging.Log().Warnf("Was not able to marshal the credential. Err: %v", err)
		return generatedJwt, err
	}
	jwtBuilder := jwt.NewBuilder().Issuer(v.did).Claim("client_id", v.did).Subject(holder).Audience([]string{audience}).Claim("kid", (*v.signingKey).KeyID())
	if v.scope != "" {
		jwtBuilder.Claim("scope", v.scope)
	}
	jwtBuilder.Claim("verifiableCredential", credentialString)

	token, err := jwtBuilder.Build()
	if err != nil {
		logging.Log().Warnf("Was not able to build a token. Err: %v", err)
		return generatedJwt, err
	}

	return token, err
}

// helper method to get a signing algorithm by name
func getAlgorithm(algString string) (algo jwa.SignatureAlgorithm, err error) {
	for _, algorithm := range jwa.SignatureAlgorithms() {
		if algorithm.String() == algString {
			return algorithm, err
		}
	}
	logging.Log().Warnf("Algorithm %s is not supported.", algString)
	return algo, errors.New("no_such_algorithm")
}

// creates an authenticationRequest string from the given parameters
func (v *Verifier) createAuthenticationRequest(base string, redirect_uri string, state string) string {

	// We use a template to generate the final string
	template := "{{base}}?response_type=vp_token" +
		"&response_mode=direct_post" +
		"&client_id={{client_id}}" +
		"&redirect_uri={{redirect_uri}}" +
		"&state={{state}}" +
		"&nonce={{nonce}}"

	if v.scope != "" {
		template = template + "&scope={{scope}}"
	}

	t := fasttemplate.New(template, "{{", "}}")
	authRequest := t.ExecuteString(map[string]interface{}{
		"base":         base,
		"scope":        v.scope,
		"client_id":    v.did,
		"redirect_uri": redirect_uri,
		"state":        state,
		"nonce":        generateNonce(),
	})

	return authRequest

}

// generate a random nonce
func generateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}
