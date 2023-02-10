package main

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	qrcode "github.com/skip2/go-qrcode"
	"go.uber.org/zap"
)

const frontendPrefix = "/"

type Frontend struct {
	server *Server
}

// setupVerifier creates and setups the Issuer routes
func setupFrontend(s *Server) {

	frontend := &Frontend{s}

	// Define the prefix for Verifier routes
	frontendRoutes := s.Group(frontendPrefix)

	// Pages

	// Display a QR code for mobile wallet or a link for enterprise wallet
	frontendRoutes.Get("/displayqr", frontend.VerifierPageDisplayQRSIOP)

	// Error page when login session has expired without the user sending the credential
	frontendRoutes.Get("/loginexpired", frontend.VerifierPageLoginExpired)

	// Page displaying the received credential, after successful login
	frontendRoutes.Get("/receivecredential/:state", frontend.VerifierPageReceiveCredential)

	// Allow simulation of accessing protected resources, after successful login
	frontendRoutes.Get("/accessprotectedservice", frontend.VerifierPageAccessProtectedService)
	frontendRoutes.Post("/accessService", frontend.VerifierPageAccessServicePost)
	frontendRoutes.Get("/accessService", frontend.VerifierPageAccessServiceGet)
}

func (f *Frontend) VerifierPageDisplayQRSIOP(c *fiber.Ctx) error {

	// Generate the state that will be used for checking expiration and also successful logon
	state := generateNonce()

	// Create an entry in storage that will expire.
	// The entry is identified by the nonce
	f.server.storage.Set(state, []byte("pending"), 200*time.Second)

	// This is the endpoint inside the QR that the wallet will use to send the VC/VP
	redirect_uri := c.Protocol() + "://" + c.Hostname() + verifierPrefix + "/authenticationresponse"

	// Create the Authentication Request
	authRequest := createAuthenticationRequest(f.server.verifierDID, redirect_uri, state)
	f.server.logger.Info("AuthRequest", authRequest)

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
		"verifierPrefix": frontendPrefix,
		"qrcode":         base64Img,
		"prefix":         frontendPrefix,
		"state":          state,
	}
	return c.Render("verifier_present_qr", m)
}

func (f *Frontend) VerifierPageLoginExpired(c *fiber.Ctx) error {
	m := fiber.Map{
		"prefix": frontendPrefix,
	}
	return c.Render("verifier_loginexpired", m)
}

func (f *Frontend) VerifierPageReceiveCredential(c *fiber.Ctx) error {

	// Get the state as a path parameter
	state := c.Params("state")

	// get the credential from the storage
	rawCred, _ := f.server.storage.Get(state)
	if len(rawCred) == 0 {
		// Render an error
		m := fiber.Map{
			"error": "No credential found",
		}
		return c.Render("displayerror", m)
	}

	claims := string(rawCred)

	// Create an access token from the credential
	accessToken, err := f.server.verifierVault.CreateAccessToken(claims, f.server.cfg.String("verifier.id"))
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
		"verifierPrefix": frontendPrefix,
		"claims":         claims,
		"prefix":         frontendPrefix,
	}
	return c.Render("verifier_receivedcredential", m)
}

func (f *Frontend) VerifierPageAccessServiceGet(c *fiber.Ctx) error {

	protected := f.server.cfg.String("verifier.protectedResource.url")
	// Render
	m := fiber.Map{
		"protectedService": protected,
		"verifierPrefix":   verifierPrefix,
	}
	return c.Render("frontendPrefix", m)
}

func (f *Frontend) VerifierPageAccessServicePost(c *fiber.Ctx) error {
	var code int
	var returnBody []byte
	var errors []error

	// Get the access token from the cookie
	accessToken := c.Cookies("dbsamvf")
	service := &AccessServiceForm{}
	if err := c.BodyParser(service); err != nil {
		f.server.logger.Infof("Error parsing: %s", err)
		return err
	}
	f.server.logger.Errorw(string(c.Body()))
	// Prepare to GET to the url
	agent := fiber.Get(service.Url)

	// Set the Authentication header
	agent.Set("Authorization", "Bearer "+accessToken)

	agent.Set("accept", "application/json")
	code, returnBody, errors = agent.Bytes()
	if len(errors) > 0 {
		f.server.logger.Errorw("error calling backend at "+service.Url, zap.Errors("errors", errors))
		return fmt.Errorf("error calling backend as %s: %v", service.Url, errors[0])
	}

	// Render
	m := fiber.Map{
		"protectedService": service.Url,
		"verifierPrefix":   frontendPrefix,
		"code":             code,
		"returnBody":       string(returnBody),
	}
	return c.Render("verifier_request_service", m)
}

func (f *Frontend) VerifierPageAccessProtectedService(c *fiber.Ctx) error {

	var code int
	var returnBody []byte
	var errors []error

	// Get the access token from the cookie
	accessToken := c.Cookies("dbsamvf")

	// Check if the user has configured a protected service to access
	protected := f.server.cfg.String("verifier.protectedResource.url")
	if len(protected) > 0 {

		// Prepare to GET to the url
		agent := fiber.Get(protected)

		// Set the Authentication header
		agent.Set("Authorization", "Bearer "+accessToken)

		agent.Set("accept", "application/json")
		code, returnBody, errors = agent.Bytes()
		if len(errors) > 0 {
			f.server.logger.Errorw("error calling SSI Kit", zap.Errors("errors", errors))
			return fmt.Errorf("error calling SSI Kit: %v", errors[0])
		}

	}

	// Render
	m := fiber.Map{
		"verifierPrefix": frontendPrefix,
		"accesstoken":    accessToken,
		"protected":      protected,
		"code":           code,
		"returnBody":     string(returnBody),
	}
	return c.Render("verifier_protectedservice", m)
}
