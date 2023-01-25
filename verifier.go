package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/hesusruiz/vcutils/yaml"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/valyala/fasttemplate"
	"go.uber.org/zap"
)

type Verifier struct {
	server *Server
}

// setupVerifier creates and setups the Issuer routes
func setupVerifier(s *Server) {

	verifier := &Verifier{s}

	// Define the prefix for Verifier routes
	verifierRoutes := s.Group(verifierPrefix)

	// Routes consist of a set of pages rendering HTML using templates and a set of APIs

	// The JWKS endpoint
	jwks_uri := s.cfg.String("verifier.uri_prefix") + s.cfg.String("verifier.jwks_uri")
	s.Get(jwks_uri, s.VerifierAPIJWKS)

	// Pages

	// Display a QR code for mobile wallet or a link for enterprise wallet
	verifierRoutes.Get("/displayqr", verifier.VerifierPageDisplayQRSIOP)

	// Error page when login session has expired without the user sending the credential
	verifierRoutes.Get("/loginexpired", verifier.VerifierPageLoginExpired)

	// For same-device logins (e.g., with the enterprise wallet)
	verifierRoutes.Get("/startsiopsamedevice", verifier.VerifierPageStartSIOPSameDevice)

	// Page displaying the received credential, after successful login
	verifierRoutes.Get("/receivecredential/:state", verifier.VerifierPageReceiveCredential)

	// Allow simulation of accessing protected resources, after successful login
	verifierRoutes.Get("/accessprotectedservice", verifier.VerifierPageAccessProtectedService)

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

func (v *Verifier) VerifierPageDisplayQRSIOP(c *fiber.Ctx) error {

	// Generate the state that will be used for checking expiration and also successful logon
	state := generateNonce()

	// Create an entry in storage that will expire.
	// The entry is identified by the nonce
	v.server.storage.Set(state, []byte("pending"), 200*time.Second)

	// This is the endpoint inside the QR that the wallet will use to send the VC/VP
	redirect_uri := c.Protocol() + "://" + c.Hostname() + verifierPrefix + "/authenticationresponse"

	// Create the Authentication Request
	authRequest := createAuthenticationRequest(v.server.verifierDID, redirect_uri, state)
	v.server.logger.Info("AuthRequest", authRequest)

	// Create the QR code for cross-device SIOP
	png, err := qrcode.Encode(authRequest, qrcode.Medium, 256)
	if err != nil {
		return err
	}

	// Convert the image data to a dataURL
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	// Render the page
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"qrcode":         base64Img,
		"prefix":         verifierPrefix,
		"state":          state,
	}
	return c.Render("verifier_present_qr", m)
}

func (v *Verifier) VerifierPageLoginExpired(c *fiber.Ctx) error {
	m := fiber.Map{
		"prefix": verifierPrefix,
	}
	return c.Render("verifier_loginexpired", m)
}

func (v *Verifier) VerifierPageStartSIOPSameDevice(c *fiber.Ctx) error {

	state := c.Query("state")

	const scope = "dsba.credentials.presentation.PacketDeliveryService"
	const response_type = "vp_token"
	redirect_uri := c.Protocol() + "://" + c.Hostname() + verifierPrefix + "/authenticationresponse"

	// template := "https://hesusruiz.github.io/faster/?scope={{scope}}" +
	// 	"&response_type={{response_type}}" +
	// 	"&response_mode=post" +
	// 	"&client_id={{client_id}}" +
	// 	"&redirect_uri={{redirect_uri}}" +
	// 	"&state={{state}}" +
	// 	"&nonce={{nonce}}"

	walletUri := c.Protocol() + "://" + c.Hostname() + walletPrefix + "/selectcredential"
	template := walletUri + "/?scope={{scope}}" +
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
	fmt.Println(str)

	return c.Redirect(str)
}

func (v *Verifier) VerifierPageReceiveCredential(c *fiber.Ctx) error {

	// Get the state as a path parameter
	state := c.Params("state")

	// get the credential from the storage
	rawCred, _ := v.server.storage.Get(state)
	if len(rawCred) == 0 {
		// Render an error
		m := fiber.Map{
			"error": "No credential found",
		}
		return c.Render("displayerror", m)
	}

	claims := string(rawCred)

	// Create an access token from the credential
	accessToken, err := v.server.verifierVault.CreateAccessToken(claims, v.server.cfg.String("verifier.id"))
	if err != nil {
		return err
	}

	// Set it in a cookie
	cookie := new(fiber.Cookie)
	cookie.Name = "dbsamvf"
	cookie.Value = string(accessToken)
	cookie.Expires = time.Now().Add(1 * time.Hour)

	// Set cookie
	c.Cookie(cookie)

	// Set also the access token in the Authorization field of the response header
	bearer := "Bearer " + string(accessToken)
	c.Set("Authorization", bearer)

	// Render
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"claims":         claims,
		"prefix":         verifierPrefix,
	}
	return c.Render("verifier_receivedcredential", m)
}

func (v *Verifier) VerifierPageAccessProtectedService(c *fiber.Ctx) error {

	var code int
	var returnBody []byte
	var errors []error

	// Get the access token from the cookie
	accessToken := c.Cookies("dbsamvf")

	// Check if the user has configured a protected service to access
	protected := v.server.cfg.String("verifier.protectedResource.url")
	if len(protected) > 0 {

		// Prepare to GET to the url
		agent := fiber.Get(protected)

		// Set the Authentication header
		agent.Set("Authorization", "Bearer "+accessToken)

		agent.Set("accept", "application/json")
		code, returnBody, errors = agent.Bytes()
		if len(errors) > 0 {
			v.server.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
			return fmt.Errorf("error calling SSI Kit: %v", errors[0])
		}

	}

	// Render
	m := fiber.Map{
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
		"accesstoken":    accessToken,
		"protected":      protected,
		"code":           code,
		"returnBody":     string(returnBody),
	}
	return c.Render("verifier_protectedservice", m)
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

	credential := vp.String("credential")
	// Validate the credential

	// Set the credential in storage, and wait for the polling from client
	v.server.storage.Set(state, []byte(credential), 10*time.Second)

	return c.SendString("ok")
}

type verifiableCredential struct {
	Credential *json.RawMessage `json:"credential"`
}

func (v *Verifier) VerifierAPIAuthenticationResponse(c *fiber.Ctx) error {

	// Get the state
	state := c.Query("state")

	// We should receive the credential in the body as JSON
	body := c.Body()
	v.server.logger.Infof("Authenticate for state '%s' with %s", state, body)
	// Decode into a map

	vc := &verifiableCredential{}
	json.Unmarshal(body, vc)

	// Validate the credential
	v.server.logger.Infof("Store credential %s", *vc.Credential)
	// Set the credential in storage, and wait for the polling from client
	v.server.storage.Set(state, *vc.Credential, 10*time.Second)

	v.server.logger.Infof("Stored for state %s", state)
	return c.SendString("ok")
}

func (v *Verifier) VerifierPageDisplayQR(c *fiber.Ctx) error {

	if sameDevice {
		return v.VerifierPageStartSIOPSameDevice(c)
	}

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
		"issuerPrefix":   issuerPrefix,
		"verifierPrefix": verifierPrefix,
		"walletPrefix":   walletPrefix,
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
