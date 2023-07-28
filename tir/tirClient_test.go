package tir

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

const ISHARE_EXAMPLE = "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/suites/jws-2020/v1\"],\"id\":\"did:elsi:eu.eori.denhaag19902304\",\"verificationMethod\":[{\"id\":\"did:elsi:eu.eori.denhaag19902304#key-assertion\",\"type\":\"JsonWebKey2020\",\"controller\":\"did:elsi:eu.eori.denhaag19902304\",\"publicKeyJwk\":{\"kid\":\"key-assertion\",\"kty\":\"RSA\",\"x5c\":[\"MIIEzDCCA7SgAwIBAgIIU2Bx+k6hNH8wDQYJKoZIhvcNAQELBQAwPDE6MDgGA1UEAwwxVEVTVCBpU0hBUkUgRVUgSXNzdWluZyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBHNTAeFw0yMzA1MjAwOTQ5NThaFw0yNjA1MTkwOTQ5NTdaMFgxETAPBgNVBAMMCG1hbnNwYWNlMSAwHgYDVQQFExdFVS5FT1JJLkRFTkhBQUcxOTkwMjMwNDESMBAGA1UECgwJU2VydmJsb2NrMQ0wCwYDVQQGEwRJRS1EMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlIeNCe+HoNrmGHdi3ZWnu4jmuaRRgog+JV0+7hMBhSDTI/gwcfhn9xIJ8qpmvGm2PxHkHX4o1VLDg/02Ii0mkyPg9Tc0e6x0rCMwRiN1ANShTRwyPumcOoA9FiKR6tPjwm32sOEqxw9Cs2PWtsWpONlDRySWmM8l99o4tnsQHKWNnsJPwgURwXbmGNKRKUePIRmU4fA0k/NZSpy6rkjYpLkXWt3RaPhsqp7ZR4cNU9/MKJgA9EsDJgXkkMYh90/lBoU8Q4GBOgOF4Rk4iuIQUhN0DcBaNZKtN4BYxmT91I7IXnUfTo1LjSjSFozS59ERNsqEk5AvoMcjgCHhsuLVYY8o9rU7e+whO9U43wNhI9CzBvUZM7dr66hi4Rn10w4aV5Fufzs6w+wMRKjDVRLZTUWrpyW9O6Tq7qpUC0k7HwXTZryGP6LORz/9isW4NlgLD5P3ayK+QS7WfgxkGZF19y2UHeC1iCw9C8F6OY1T4ScMc3xLBGfIE/GqYdq/tj6fafRJvL9al5Yp9+VBw1HOXnwdWuixT7AXQOKX5/l6HxYlzgOMJpKdB0MKIP9AkEEzlE7P90AiUagunc/pLzqVJSlpL7EMMKFtU+uBLB6Jv837wHc/QotFdDkCjqxN7w2GUIjpFQImoYiuBmNC/vUmkVZk7UHfjDOIbuPyvLHkf6kCAwEAAaOBtTCBsjAfBgNVHSMEGDAWgBRtxWWJy9+RVNFrPLcCpS7NimiQHTAnBgNVHSUEIDAeBggrBgEFBQcDAgYIKwYBBQUHAwQGCCsGAQUFBwMBMDcGCCsGAQUFBwEDBCswKTAIBgYEAI5GAQEwCAYGBACORgEEMBMGBgQAjkYBBjAJBgcEAI5GAQYCMB0GA1UdDgQWBBTaFjV/ENI1bpHim18LXUXoglLjrzAOBgNVHQ8BAf8EBAMCBsAwDQYJKoZIhvcNAQELBQADggEBAJEdDj9d8KNbIwgC066JXP1cQSaI9yeEoCWWx2RVQrZzcsYyNWyJRZVgHP56Q4U/HTB76JZ9yGhqD8Ns2XiUCcKAxhz5Lt+bM0FLrYKoGV37+ke7PhM4+QlGOZx8y9w9ASqwgxMGVyj9KLp5u+nHVgxcR7h2LKqpC7c6SiLREdtnvqOEB8/OGG57vZ5ruZG6f3H0A03LI7z0vBUbfhlptoC4lB6I7FG0Z3buu3R3Wc6LX6vWFxiC34MGD8y71tSYUgGlAcm+HjU/6o3L/ajVkYhS3XbrrpJ2X/2dfJY5m2ZyQAHKsHH1WczXG/i2oPgXhy/2esdl5H/AXkyHMARY2Dk=\"]}}],\"authentication\":[\"did:elsi:eu.eori.denhaag19902304#key-assertion\"],\"assertionMethod\":[\"did:elsi:eu.eori.denhaag19902304#key-assertion\"]}"

func TestDidRegistry(t *testing.T) {
	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		if req.URL.String() == "/v4/identifiers/did:elsi:eu.eori.denhaag19902304" {
			rw.Header().Set("Content-Type", "json")
			// Send response to be tested
			rw.Write([]byte(ISHARE_EXAMPLE))
		} else {
			rw.WriteHeader(404)
		}
	}))
	// Close the server when test finishes
	defer server.Close()

	tirClient := TirHttpClient{server.Client()}
	trusted := tirClient.issuerExists(server.URL, "did:elsi:eu.eori.denhaag19902304")
	assert.Equal(t, true, trusted, "Should return that issuer is trusted")

	trusted = tirClient.issuerExists(server.URL, "did:elsi:someThingElse")
	assert.Equal(t, false, trusted, "Should return that issuer is not trusted")
}
