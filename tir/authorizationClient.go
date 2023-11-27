package tir

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/fiware/VCVerifier/logging"
	api "github.com/fiware/VCVerifier/openapi"
)

const TOKEN_ENDPOINT = "/v4/token_m2m"

// http client to be used
var ErrorTokenEndpointNoResponse = errors.New("no_response_from_token_endpoint")

type HttpGetClient interface {
	Get(tirAddress string, tirPath string) (resp *http.Response, err error)
}

type AuthorizingHttpClient struct {
	httpClient    HttpClient
	tokenProvider *TokenProvider
}

type NoAuthHttpClient struct {
	httpClient HttpClient
}

func (nac NoAuthHttpClient) Get(tirAddress string, tirPath string) (resp *http.Response, err error) {
	urlString := buildUrlString(tirAddress, tirPath)
	return nac.httpClient.Get(urlString)
}

func (ac AuthorizingHttpClient) Get(tirAddress string, tirPath string) (resp *http.Response, err error) {
	urlString := buildUrlString(tirAddress, tirPath)
	resp, err = ac.httpClient.Get(urlString)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode != 403 {
		return resp, err
	}
	// repeat with auth

}

func buildUrlString(address string, path string) string {
	if strings.HasSuffix(address, "/") {
		if strings.HasPrefix(path, "/") {
			return address + strings.TrimPrefix(path, "/")
		} else {
			return address + path
		}
	} else {
		if strings.HasPrefix(path, "/") {
			return address + path
		} else {
			return address + "/" + path
		}
	}
}

func (ac AuthorizingHttpClient) handleAuthorization(tirAddress string) (bearerToken string, err error) {
	vc, err := (*ac.tokenProvider).GetAuthCredential()
	if err != nil {
		logging.Log().Warnf("No credential configured for auth. Err: %v", err)
		return bearerToken, err
	}
	(*ac.tokenProvider).GetSignedToken(vc, tirAddress)
}

func (ac AuthorizingHttpClient) postVpToken(tokenHost string, vpToken string, presentationSubmission string, scope string) (idToken string, accessToken string, err error) {

	formRequest := url.Values{}
	formRequest.Add("grant_type", "vp_token")
	formRequest.Add("vp_token", vpToken)
	formRequest.Add("presentation_submission", presentationSubmission)
	formRequest.Add("scope", scope)

	tokenHttpRequest, err := http.NewRequest("POST", buildUrlString(tokenHost, TOKEN_ENDPOINT), strings.NewReader(formRequest.Encode()))
	if err != nil {
		logging.Log().Warnf("Was not able to create token request. Err: %v", err)
		return idToken, accessToken, err
	}

	tokenHttpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenHttpResponse, err := ac.httpClient.Do(tokenHttpRequest) // evaluate the results
	if err != nil {
		logging.Log().Warnf("Did not receive a valid token response. Err: %v", err)
		return idToken, accessToken, err
	}
	if tokenHttpResponse == nil {
		logging.Log().Warn("Did not receive any response from the token endpoint.")
		return idToken, accessToken, ErrorTokenEndpointNoResponse
	}
	if tokenHttpResponse.StatusCode != 200 {
		logging.Log().Infof("Did not receive an ok from the token request. Was %s", logging.PrettyPrintObject(tokenHttpResponse))
		return idToken, accessToken, err
	}
	if tokenHttpResponse.Body == nil {
		logging.Log().Info("Received an empty body for the token request.")
		return idToken, accessToken, err
	}

	var tokenResponse api.TokenResponse

	err = json.NewDecoder(tokenHttpResponse.Body).Decode(&tokenResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the token response.")
		return idToken, accessToken, err
	}
	return tokenResponse.IdToken, tokenResponse.AccessToken, err
}
