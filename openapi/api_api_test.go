package openapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fiware/VCVerifier/logging"
	verifier "fiware/VCVerifier/verifier"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwk"
)

type mockVerifier struct {
	mockJWTString        string
	mockQR               string
	mockConnectionString string
	mockAuthRequest      string
	mockJWKS             jwk.Set
	mockRedirect         verifier.RedirectResponse
	mockExpiration       int64
	mockError            error
}

func (mV *mockVerifier) ReturnLoginQR(host string, protocol string, callback string, redircetUri string, sessionId string) (qr string, err error) {
	return mV.mockQR, mV.mockError
}
func (mV *mockVerifier) StartSiopFlow(host string, protocol string, callback string, sessionId string) (connectionString string, err error) {
	return mV.mockConnectionString, mV.mockError
}
func (mV *mockVerifier) StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string) (authenticationRequest string, err error) {
	return mV.mockAuthRequest, mV.mockError
}
func (mV *mockVerifier) GetToken(grantType string, authorizationCode string, redirectUri string) (jwtString string, expiration int64, err error) {
	return mV.mockJWTString, mV.mockExpiration, mV.mockError
}
func (mV *mockVerifier) GetJWKS() jwk.Set {
	return mV.mockJWKS
}
func (mV *mockVerifier) AuthenticationResponse(state string, verifiableCredentials []map[string]interface{}, holder string) (sameDevice verifier.RedirectResponse, err error) {
	return mV.mockRedirect, mV.mockError
}

func TestGetToken(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName           string
		testGrantType      string
		testCode           string
		testRedirectUri    string
		mockJWTString      string
		mockExpiration     int64
		mockError          error
		expectedStatusCode int
		expectedResponse   TokenResponse
		expectedError      ErrorMessage
	}
	tests := []test{
		{"If a valid request is received a token should be responded.", "authorization_code", "my-auth-code", "http://my-redirect.org", "theJWT", 10, nil, 200, TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT"}, ErrorMessage{}},
		{"If no grant type is provided, the request should fail.", "", "my-auth-code", "http://my-redirect.org", "theJWT", 10, nil, 400, TokenResponse{}, ErrorMessagNoGrantType},
		{"If no auth code is provided, the request should fail.", "authorization_code", "", "http://my-redirect.org", "theJWT", 10, nil, 400, TokenResponse{}, ErrorMessageNoCode},
		{"If no redirect uri is provided, the request should fail.", "authorization_code", "my-auth-code", "", "theJWT", 10, nil, 400, TokenResponse{}, ErrorMessageNoRedircetUri},
		{"If the verify returns an error, a 403 should be answerd.", "authorization_code", "my-auth-code", "http://my-redirect.org", "", 10, errors.New("invalid"), 403, TokenResponse{}, ErrorMessage{}},
	}

	for _, tc := range tests {

		logging.Log().Info("TestGetToken +++++++++++++++++ Running test: ", tc.testName)

		recorder := httptest.NewRecorder()
		testContext, _ := gin.CreateTestContext(recorder)
		apiVerifier = &mockVerifier{mockJWTString: tc.mockJWTString, mockExpiration: tc.mockExpiration, mockError: tc.mockError}

		formArray := []string{}

		if tc.testGrantType != "" {
			formArray = append(formArray, "grant_type="+tc.testGrantType)
		}
		if tc.testCode != "" {
			formArray = append(formArray, "code="+tc.testCode)
		}
		if tc.testRedirectUri != "" {
			formArray = append(formArray, "redirect_uri="+tc.testRedirectUri)
		}

		body := bytes.NewBufferString(strings.Join(formArray, "&"))
		testContext.Request, _ = http.NewRequest("POST", "/", body)
		testContext.Request.Header.Add("Content-Type", gin.MIMEPOSTForm)

		GetToken(testContext)

		if recorder.Code != tc.expectedStatusCode {
			t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
			continue
		}

		if tc.expectedStatusCode == 400 {
			errorBody, _ := ioutil.ReadAll(recorder.Body)
			errorMessage := ErrorMessage{}
			json.Unmarshal(errorBody, &errorMessage)
			if errorMessage != tc.expectedError {
				t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
				continue
			}
			continue
		}

		tokenResponse := TokenResponse{}
		if tc.expectedResponse != tokenResponse {
			body, _ := ioutil.ReadAll(recorder.Body)
			err := json.Unmarshal(body, &tokenResponse)
			if err != nil {
				t.Errorf("%s - Was not able to unmarshal the token response. Err: %v.", tc.testName, err)
				continue
			}
			if tokenResponse != tc.expectedResponse {
				t.Errorf("%s - Expected token response %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedResponse), logging.PrettyPrintObject(tokenResponse))
				continue
			}
		}

	}
}

func TestStartSIOPSameDevice(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName           string
		testState          string
		testRedirectPath   string
		testRequestAddress string
		mockRedirect       string
		mockError          error
		expectedStatusCode int
		expectedLocation   string
	}

	tests := []test{
		{"If all neccessary parameters provided, a valid redirect should be returned.", "my-state", "/my-redirect", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 302, "http://host.org/api/v1/authentication_response"},
		{"If no path is provided, the default redirect should be returned.", "my-state", "", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 302, "http://host.org/api/v1/authentication_response"},
		{"If no state is provided, a 400 should be returned.", "", "", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 400, ""},
		{"If the verifier returns an error, a 500 should be returned.", "my-state", "/", "http://host.org", "http://host.org/api/v1/authentication_response", errors.New("verifier_failure"), 500, ""},
	}

	for _, tc := range tests {

		logging.Log().Info("TestStartSIOPSameDevice +++++++++++++++++ Running test: ", tc.testName)

		recorder := httptest.NewRecorder()
		testContext, _ := gin.CreateTestContext(recorder)
		apiVerifier = &mockVerifier{mockAuthRequest: tc.mockRedirect, mockError: tc.mockError}

		testParameters := []string{}
		if tc.testState != "" {
			testParameters = append(testParameters, "state="+tc.testState)
		}
		if tc.testRedirectPath != "" {
			testParameters = append(testParameters, "redirect_path="+tc.testRedirectPath)
		}

		testContext.Request, _ = http.NewRequest("GET", tc.testRequestAddress+"/?"+strings.Join(testParameters, "&"), nil)
		StartSIOPSameDevice(testContext)

		if recorder.Code != tc.expectedStatusCode {
			t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
			continue
		}
		if tc.expectedStatusCode != 302 {
			// everything other is an error, we dont care about the details
			continue
		}

		location := recorder.Result().Header.Get("Location")
		if location != tc.expectedLocation {
			t.Errorf("%s - Expected location %s but was %s.", tc.testName, tc.expectedLocation, location)
		}
	}
}

func TestVerifierAPIAuthenticationResponse(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName           string
		sameDevice         bool
		testState          string
		testVPToken        string
		mockError          error
		mockRedirect       verifier.RedirectResponse
		expectedStatusCode int
		expectedRedirect   string
		expectedError      ErrorMessage
	}

	tests := []test{
		{"If a same-device flow is authenticated, a valid redirect should be returned.", true, "my-state", getValidVPToken(), nil, verifier.RedirectResponse{RedirectTarget: "http://my-verifier.org", Code: "my-code", SessionId: "my-session-id"}, 302, "http://my-verifier.org?state=my-session-id&code=my-code", ErrorMessage{}},
		{"If a cross-device flow is authenticated, a simple ok should be returned.", false, "my-state", getValidVPToken(), nil, verifier.RedirectResponse{}, 200, "", ErrorMessage{}},
		{"If the same-device flow responds an error, a 400 should be returend", true, "my-state", getValidVPToken(), errors.New("verification_error"), verifier.RedirectResponse{}, 400, "", ErrorMessage{Summary: "verification_error"}},
		{"If no state is provided, a 400 should be returned.", true, "", getValidVPToken(), nil, verifier.RedirectResponse{}, 400, "", ErrorMessageNoState},
		{"If an no token is provided, a 400 should be returned.", true, "my-state", "", nil, verifier.RedirectResponse{}, 400, "", ErrorMessageNoToken},
		{"If a token with invalid credentials is provided, a 400 should be returned.", true, "my-state", getNoVCVPToken(), nil, verifier.RedirectResponse{}, 400, "", ErrorMessageUnableToDecodeCredential},
		{"If a token with an invalid holder is provided, a 400 should be returned.", true, "my-state", getNoHolderVPToken(), nil, verifier.RedirectResponse{}, 400, "", ErrorMessageUnableToDecodeHolder},
	}

	for _, tc := range tests {

		logging.Log().Info("TestVerifierAPIAuthenticationResponse +++++++++++++++++ Running test: ", tc.testName)

		recorder := httptest.NewRecorder()
		testContext, _ := gin.CreateTestContext(recorder)
		apiVerifier = &mockVerifier{mockRedirect: tc.mockRedirect, mockError: tc.mockError}

		formArray := []string{}

		if tc.testVPToken != "" {
			formArray = append(formArray, "vp_token="+tc.testVPToken)
		}

		requestAddress := "http://my-verifier.org/"
		if tc.testState != "" {
			requestAddress = requestAddress + "?state=" + tc.testState
		}

		body := bytes.NewBufferString(strings.Join(formArray, "&"))
		testContext.Request, _ = http.NewRequest("POST", requestAddress, body)
		testContext.Request.Header.Add("Content-Type", gin.MIMEPOSTForm)

		VerifierAPIAuthenticationResponse(testContext)

		if tc.expectedStatusCode == 400 {
			errorBody, _ := ioutil.ReadAll(recorder.Body)
			errorMessage := ErrorMessage{}
			json.Unmarshal(errorBody, &errorMessage)
			if errorMessage != tc.expectedError {
				t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
				continue
			}
			continue
		}

		if tc.sameDevice && tc.expectedStatusCode != 302 && tc.expectedStatusCode != recorder.Code {
			t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
			continue
		}

		if tc.sameDevice {
			location := recorder.Result().Header.Get("Location")
			if location != tc.expectedRedirect {
				t.Errorf("%s - Expected location %s but was %s.", tc.testName, tc.expectedRedirect, location)
				continue
			}
			continue
		}

		if recorder.Code != tc.expectedStatusCode {
			t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
			continue
		}
		if tc.expectedStatusCode != 200 {
			continue
		}

	}
}

func TestVerifierAPIStartSIOP(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName                 string
		testState                string
		testCallback             string
		testAddress              string
		mockConnectionString     string
		mockError                error
		expectedStatusCode       int
		expectedConnectionString string
		expectedError            ErrorMessage
	}

	tests := []test{
		{"If all parameters are present, a siop flow should be started.", "my-state", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", nil, 200, "openid://mockConnectionString", ErrorMessage{}},
		{"If no state is present, a 400 should be returned.", "", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", nil, 400, "", ErrorMessageNoState},
		{"If no callback is present, a 400 should be returned.", "my-state", "", "http://my-verifier.org", "openid://mockConnectionString", nil, 400, "", ErrorMessageNoCallback},
		{"If the verifier cannot start the flow, a 500 should be returend.", "my-state", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", errors.New("verifier_failure"), 500, "", ErrorMessageNoState},
	}

	for _, tc := range tests {

		logging.Log().Info("TestVerifierAPIStartSIOP +++++++++++++++++ Running test: ", tc.testName)

		recorder := httptest.NewRecorder()
		testContext, _ := gin.CreateTestContext(recorder)
		apiVerifier = &mockVerifier{mockConnectionString: tc.mockConnectionString, mockError: tc.mockError}

		testParameters := []string{}
		if tc.testState != "" {
			testParameters = append(testParameters, "state="+tc.testState)
		}
		if tc.testCallback != "" {
			testParameters = append(testParameters, "client_callback="+tc.testCallback)
		}

		testContext.Request, _ = http.NewRequest("GET", tc.testAddress+"/?"+strings.Join(testParameters, "&"), nil)
		VerifierAPIStartSIOP(testContext)

		if recorder.Code != tc.expectedStatusCode {
			t.Errorf("%s - Expected code %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
			continue
		}
		if tc.expectedStatusCode == 500 {
			// something internal, we dont care about the details
			continue
		}

		if tc.expectedStatusCode == 400 {
			errorBody, _ := ioutil.ReadAll(recorder.Body)
			errorMessage := ErrorMessage{}
			json.Unmarshal(errorBody, &errorMessage)
			if errorMessage != tc.expectedError {
				t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
				continue
			}
			continue
		}
		body, _ := ioutil.ReadAll(recorder.Body)
		connectionString := string(body)
		if connectionString != tc.expectedConnectionString {
			t.Errorf("%s - Expected connectionString %s but was %s.", tc.testName, tc.expectedConnectionString, connectionString)
		}
	}
}

func getValidVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAidmVyaWZpYWJsZUNyZWRlbnRpYWwiOiBbCiAgICB7CiAgICAgICJ0eXBlcyI6IFsKICAgICAgICAiUGFja2V0RGVsaXZlcnlTZXJ2aWNlIiwKICAgICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiCiAgICAgIF0sCiAgICAgICJAY29udGV4dCI6IFsKICAgICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAgICJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIKICAgICAgXSwKICAgICAgImNyZWRlbnRpYWxzU3ViamVjdCI6IHt9LAogICAgICAiYWRkaXRpb25hbFByb3AxIjoge30KICAgIH0KICBdLAogICJpZCI6ICJlYmM2ZjFjMiIsCiAgImhvbGRlciI6ICJkaWQ6a2V5Ono2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgInByb29mIjogewogICAgInR5cGUiOiAiSnNvbldlYlNpZ25hdHVyZTIwMjAiLAogICAgImNyZWF0b3IiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgiLAogICAgImNyZWF0ZWQiOiAiMjAyMy0wMS0wNlQwNzo1MTozNloiLAogICAgInZlcmlmaWNhdGlvbk1ldGhvZCI6ICJkaWQ6a2V5Ono2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCN6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgiLAogICAgImp3cyI6ICJleUppTmpRaU9tWmhiSE5sTENKamNtbDBJanBiSW1JMk5DSmRMQ0poYkdjaU9pSkZaRVJUUVNKOS4uNnhTcW9aamEwTndqRjBhZjlaa25xeDNDYmg5R0VOdW5CZjlDOHVMMnVsR2Z3dXMzVUZNX1puaFBqV3RIUGwtNzJFOXAzQlQ1ZjJwdFpvWWt0TUtwREEiCiAgfQp9"
}

func getNoVCVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAiaWQiOiAiZWJjNmYxYzIiLAogICJob2xkZXIiOiB7CiAgICAiaWQiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgiCiAgfSwKICAicHJvb2YiOiB7CiAgICAidHlwZSI6ICJKc29uV2ViU2lnbmF0dXJlMjAyMCIsCiAgICAiY3JlYXRvciI6ICJkaWQ6a2V5Ono2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiY3JlYXRlZCI6ICIyMDIzLTAxLTA2VDA3OjUxOjM2WiIsCiAgICAidmVyaWZpY2F0aW9uTWV0aG9kIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoI3o2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiandzIjogImV5SmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZExDSmhiR2NpT2lKRlpFUlRRU0o5Li42eFNxb1pqYTBOd2pGMGFmOVprbnF4M0NiaDlHRU51bkJmOUM4dUwydWxHZnd1czNVRk1fWm5oUGpXdEhQbC03MkU5cDNCVDVmMnB0Wm9Za3RNS3BEQSIKICB9Cn0"
}

func getNoHolderVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAidmVyaWZpYWJsZUNyZWRlbnRpYWwiOiBbCiAgICB7CiAgICAgICJ0eXBlcyI6IFsKICAgICAgICAiUGFja2V0RGVsaXZlcnlTZXJ2aWNlIiwKICAgICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiCiAgICAgIF0sCiAgICAgICJAY29udGV4dCI6IFsKICAgICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAgICJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIKICAgICAgXSwKICAgICAgImNyZWRlbnRpYWxzU3ViamVjdCI6IHt9LAogICAgICAiYWRkaXRpb25hbFByb3AxIjoge30KICAgIH0KICBdLAogICJpZCI6ICJlYmM2ZjFjMiIsCiAgImhvbGRlciI6IHsKICAgICJub3RhIjogImhvbGRlciIKICB9LAogICJwcm9vZiI6IHsKICAgICJ0eXBlIjogIkpzb25XZWJTaWduYXR1cmUyMDIwIiwKICAgICJjcmVhdG9yIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJjcmVhdGVkIjogIjIwMjMtMDEtMDZUMDc6NTE6MzZaIiwKICAgICJ2ZXJpZmljYXRpb25NZXRob2QiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgjejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJqd3MiOiAiZXlKaU5qUWlPbVpoYkhObExDSmpjbWwwSWpwYkltSTJOQ0pkTENKaGJHY2lPaUpGWkVSVFFTSjkuLjZ4U3FvWmphME53akYwYWY5WmtucXgzQ2JoOUdFTnVuQmY5Qzh1TDJ1bEdmd3VzM1VGTV9abmhQald0SFBsLTcyRTlwM0JUNWYycHRab1lrdE1LcERBIgogIH0KfQ"
}
