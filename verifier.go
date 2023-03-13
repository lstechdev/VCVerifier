package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/fiware/vcverifier/back/operations"
	model "github.com/fiware/vcverifier/model"
	"github.com/gofiber/fiber/v2"
	"github.com/hesusruiz/vcutils/yaml"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/valyala/fasttemplate"
	"go.uber.org/zap"
)

type Verifier struct {
	server     *Server
	tirAddress *string
}

// setupVerifier creates and setups the Issuer routes
func setupVerifier(s *Server) {

	configuredAddress := s.cfg.String("verifier.tirAddress")

	var tirAddress *string

	if configuredAddress == "" {
		s.logger.Warn("No trusted issuer registry configured. Will not use the tir check")
		tirAddress = nil
	} else {
		s.logger.Infof("Will use tir at %s to verify the credentials.", configuredAddress)
		tirAddress = &configuredAddress
	}

	verifier := &Verifier{s, tirAddress}

	// Define the prefix for Verifier routes
	verifierRoutes := s.Group(verifierPrefix)

	// Routes consist of a set of pages rendering HTML using templates and a set of APIs

	// The JWKS endpoint
	jwks_uri := s.cfg.String("verifier.uri_prefix") + s.cfg.String("verifier.jwks_uri")
	s.Get(jwks_uri, s.VerifierAPIJWKS)

	// APIs

	// Used by the login page from the browser, to check successful login or expiration
	verifierRoutes.Get("/poll/:state", verifier.VerifierAPIPoll)

	verifierRoutes.Get("/token/:state", verifier.VerifierAPIToken)

	// Start the SIOP flows
	verifierRoutes.Get("/startsiop", verifier.VerifierAPIStartSIOP)
	verifierRoutes.Get("/authenticationrequest", verifier.VerifierAPIStartSIOP)

	// Used by the wallet (both enterprise and mobile) to send the VC/VP as Authentication Response
	verifierRoutes.Post("/authenticationresponse", verifier.VerifierAPIAuthenticationResponse)

}

type AccessServiceForm struct {
	Url string `form:"requestUrl,omitempty"`
}

func (v *Verifier) VerifierAPIPoll(c *fiber.Ctx) error {

	// get the state
	state := c.Params("state")

	// Check if session still pending
	status, _ := v.server.storage.Get(state)
	if len(status) == 0 {
		return c.SendString("expired")
	} else {
		return c.SendString(string(status))
	}

}

// retrieve token for the given session("state"-paramter)
func (v *Verifier) VerifierAPIToken(c *fiber.Ctx) error {
	v.server.logger.Info("Get the token")
	// get the state
	state := c.Params("state")

	v.server.logger.Infof("Get for state %s", state)
	// get the credential from the storage
	rawCred, _ := v.server.storage.Get(state)
	if len(rawCred) == 0 {

		v.server.logger.Infof("No credential stored for '%s'", state)
		c.Status(403)
		return errors.New("No_such_credential")
	}

	claims := string(rawCred)

	// Create an access token from the credential
	accessToken, err := v.server.verifierVault.CreateAccessToken(claims, v.server.cfg.String("verifier.id"))
	if err != nil {
		v.server.logger.Infof("Was not able to create the token. Err: %s", err)
		c.Status(500)
		return err
	}

	return c.SendString(string(accessToken))
}

func (v *Verifier) VerifierAPIStartSIOP(c *fiber.Ctx) error {

	// Get the state
	state := c.Query("state")

	const scope = "dsba.credentials.presentation.PacketDeliveryService"
	const response_type = "vp_token"
	redirect_uri := c.Protocol() + "://" + c.Hostname() + verifierPrefix + "/authenticationresponse"

	template := "openid://?scope={{scope}}" +
		"&response_type={{response_type}}" +
		"&response_mode=post" +
		"&client_id={{client_id}}" +
		"&redirect_uri={{redirect_uri}}" +
		"&state={{state}}" +
		"&nonce={{nonce}}"

	t := fasttemplate.New(template, "{{", "}}")
	str := t.ExecuteString(map[string]interface{}{
		"scope":         scope,
		"response_type": response_type,
		"client_id":     v.server.verifierDID,
		"redirect_uri":  redirect_uri,
		"state":         state,
		"nonce":         generateNonce(),
	})

	return c.SendString(str)
}

type verficationMsg struct {
	Msg string `json:"message"`
}

// VerifierAPIAuthenticationResponseVP receives a VP, extracts the VC and display a page
func (v *Verifier) VerifierAPIAuthenticationResponseVP(c *fiber.Ctx) error {

	// Get the state, which indicates the login session to which this request belongs
	state := c.Query("state")

	// We should receive the Verifiable Presentation in the body as JSON
	body := c.Body()
	fmt.Println(string(body))
	fmt.Println(string(state))

	// Decode into a map
	vp, err := yaml.ParseJson(string(body))
	if err != nil {
		v.server.logger.Errorw("invalid vp received", zap.Error(err))
		return err
	}

	credential := []byte(vp.String("credential"))
	// Validate the credential
	res, err := v.verifyCredential(credential)
	if err != nil {
		v.server.logger.Errorw("Was not able to verify credential.", zap.Error(err))
		return err
	}
	if !res {
		v.server.logger.Info("Credential is not valid.")
		return c.Status(http.StatusUnauthorized).JSON(verficationMsg{"Credential is invalid."})
	}

	// Set the credential in storage, and wait for the polling from client
	v.server.storage.Set(state, credential, 10*time.Second)

	return c.SendString("ok")
}

func (v *Verifier) verifyCredential(credential []byte) (result bool, err error) {

	var vcToVerify map[string]interface{}

	json.Unmarshal(credential, &vcToVerify)

	policies := []model.Policy{
		{Policy: "SignaturePolicy"},
		{Policy: "IssuedDateBeforePolicy"},
		{Policy: "ValidFromBeforePolicy"},
		{Policy: "ExpirationDateAfterPolicy"},
	}
	if v.tirAddress != nil {
		policies = append(policies, model.Policy{Policy: "TrustedIssuerRegistryPolicy", Argument: &model.TirArgument{RegistryAddress: *v.tirAddress}})
	}

	return operations.VerifyVC(v.server.ssiKit.auditorUrl, policies, vcToVerify)
}

type VerifiableCredential struct {
	Credential *json.RawMessage `json:"credential"`
}

func (v *Verifier) VerifierAPIAuthenticationResponse(c *fiber.Ctx) error {

	v.server.logger.Infof("Authenticate")

	// Get the state
	state := c.Query("state")

	// We should receive the credential in the body as JSON
	body := c.Body()
	v.server.logger.Infof("Authenticate for state '%s' with %s", state, body)
	// Decode into a map

	vc := &VerifiableCredential{}
	json.Unmarshal(body, vc)

	// Validate the credential
	res, err := v.verifyCredential(*vc.Credential)
	if err != nil {
		v.server.logger.Errorw("Was not able to verify credential.", zap.Error(err))
		return err
	}
	if !res {
		v.server.logger.Info("Credential is not valid.")
		return c.Status(http.StatusUnauthorized).JSON(verficationMsg{"Credential is invalid."})
	}

	v.server.logger.Infof("Store credential %s", *vc.Credential)
	// Set the credential in storage, and wait for the polling from client
	v.server.storage.Set(state, *vc.Credential, 10*time.Second)

	v.server.logger.Infof("Stored for state %s", state)
	return c.SendString("ok")
}

func (v *Verifier) VerifierPageDisplayQR(c *fiber.Ctx) error {

	// Generate the state that will be used for checking expiration
	state := generateNonce()

	// Create an entry in storage that will expire in 2 minutes
	// The entry is identified by the nonce
	// s.storage.Set(state, []byte("pending"), 2*time.Minute)
	v.server.storage.Set(state, []byte("pending"), 40*time.Second)

	// QR code for cross-device SIOP
	template := "{{protocol}}://{{hostname}}{{prefix}}/startsiop?state={{state}}"
	qrCode1, err := qrCode(template, c.Protocol(), c.Hostname(), verifierPrefix, state)
	if err != nil {
		return err
	}

	// Render index
	m := fiber.Map{
		"verifierPrefix": verifierPrefix,
		"qrcode":         qrCode1,
		"prefix":         verifierPrefix,
		"state":          state,
	}
	return c.Render("verifier_present_qr", m)
}

func qrCode(template, protocol, hostname, prefix, state string) (string, error) {

	// Construct the URL to be included in the QR
	t := fasttemplate.New(template, "{{", "}}")
	str := t.ExecuteString(map[string]interface{}{
		"protocol": protocol,
		"hostname": hostname,
		"prefix":   prefix,
		"state":    state,
	})

	// Create the QR
	png, err := qrcode.Encode(str, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}

	// Convert to a dataURL
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	return base64Img, nil

}

func createAuthenticationRequest(verifierDID string, redirect_uri string, state string) string {

	// This specifies the type of credential that the Verifier will accept
	// TODO: In this use case it is hardcoded, which is enough if the Verifier is simple and uses
	// only one type of credential for authentication its users.
	const scope = "dsba.credentials.presentation.PacketDeliveryService"

	// The response type should be 'vp_token'
	const response_type = "vp_token"

	// Response mode should be 'post'
	const response_mode = "post"

	// We use a template to generate the final string
	template := "openid://?scope={{scope}}" +
		"&response_type={{response_type}}" +
		"&response_mode={{response_mode}}" +
		"&client_id={{client_id}}" +
		"&redirect_uri={{redirect_uri}}" +
		"&state={{state}}" +
		"&nonce={{nonce}}"

	t := fasttemplate.New(template, "{{", "}}")
	authRequest := t.ExecuteString(map[string]interface{}{
		"scope":         scope,
		"response_type": response_type,
		"response_mode": response_mode,
		"client_id":     verifierDID,
		"redirect_uri":  redirect_uri,
		"state":         state,
		"nonce":         generateNonce(),
	})

	return authRequest

}
