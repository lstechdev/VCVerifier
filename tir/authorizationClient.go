package tir

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	common "github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	"golang.org/x/exp/slices"
)

const WELL_KNOWN_ENDPOINT = "/.well-known/openid-configuration"
const SCOPE_TIR_READ = "tir_read"

// http client to be used
var ErrorTokenEndpointNoResponse = errors.New("no_response_from_token_endpoint")
var ErrorMetaDataNotOk = errors.New("no_metadata_available")
var ErrorGrantTypeNotSupported = errors.New("grant_type_not_supported")
var ErrorScopeNotSupported = errors.New("scope_not_supported")

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

	bearerToken, err := ac.handleAuthorization(tirAddress)
	if err != nil {
		logging.Log().Warnf("Was not able to get a bearer token. Err: %v", err)
		return resp, err
	}

	// repeat with auth
	authenticatedRequest, err := http.NewRequest("GET", urlString, nil)
	if err != nil {
		logging.Log().Warnf("Was not able to build the authenticated request. Err: %v", err)
		return resp, err
	}
	authenticatedRequest.Header.Add("Authorization", "Bearer "+bearerToken)
	return ac.httpClient.Do(authenticatedRequest)
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

	vpToken, err := (*ac.tokenProvider).GetToken(vc, tirAddress)
	if err != nil {
		logging.Log().Warnf("Was not able to get a VP Token. Err: %v", err)
		return bearerToken, err
	}

	metaData, err := ac.getMetaData(tirAddress)
	if err != nil {
		logging.Log().Warnf("Was not able to get the openid metadata. Err: %v", err)
		return bearerToken, err
	}
	if !slices.Contains(metaData.GrantTypesSupported, common.TYPE_VP_TOKEN) {
		logging.Log().Warnf("The server does not support grant type vp_token. Config: %v", logging.PrettyPrintObject(metaData))
		return bearerToken, ErrorGrantTypeNotSupported
	}
	if !slices.Contains(metaData.ScopesSupported, SCOPE_TIR_READ) {
		logging.Log().Warnf("The server does not support scope tir_read. Config: %v", logging.PrettyPrintObject(metaData))
		return bearerToken, ErrorScopeNotSupported
	}
	// presentation submission is not yet used.
	bearerToken, err = ac.postVpToken(metaData.TokenEndpoint, vpToken, "", SCOPE_TIR_READ)
	if err != nil {
		logging.Log().Warnf("Was not able to get an access token. Err: %v", err)
	}
	return bearerToken, err

}

func (ac AuthorizingHttpClient) getMetaData(tokenHost string) (metadata common.OpenIDProviderMetadata, err error) {
	resp, err := ac.httpClient.Get(buildUrlString(tokenHost, "/.well-known/openid-configuration"))
	if err != nil {
		logging.Log().Warnf("Was not able to get openid metadata from %s. Err: %v", tokenHost, err)
		return metadata, err
	}
	if resp == nil {
		logging.Log().Warnf("Did not receive a valid response from %v.", tokenHost)
		return metadata, ErrorMetaDataNotOk
	}
	if resp.StatusCode != 200 {
		logging.Log().Warnf("Was not able to get openid metadata from %s. Response was %v.", tokenHost, resp)
		return metadata, ErrorMetaDataNotOk
	}
	if resp.Body == nil {
		logging.Log().Warnf("Did not receive a valid response from %v. Was %v", tokenHost, resp)
		return metadata, ErrorMetaDataNotOk
	}
	var metaDataResponse common.OpenIDProviderMetadata

	err = json.NewDecoder(resp.Body).Decode(&metaDataResponse)
	if err != nil {
		logging.Log().Warnf("Was not able to decode the metadata response. Err: %v", err)
		return metadata, err
	}
	return metadata, err

}

func (ac AuthorizingHttpClient) postVpToken(tokenEndpoint string, vpToken string, presentationSubmission string, scope string) (accessToken string, err error) {

	formRequest := url.Values{}
	formRequest.Add("grant_type", "vp_token")
	formRequest.Add("vp_token", vpToken)
	formRequest.Add("presentation_submission", presentationSubmission)
	formRequest.Add("scope", scope)

	tokenHttpRequest, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(formRequest.Encode()))
	if err != nil {
		logging.Log().Warnf("Was not able to create token request. Err: %v", err)
		return accessToken, err
	}

	tokenHttpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenHttpResponse, err := ac.httpClient.Do(tokenHttpRequest) // evaluate the results
	if err != nil {
		logging.Log().Warnf("Did not receive a valid token response. Err: %v", err)
		return accessToken, err
	}
	if tokenHttpResponse == nil {
		logging.Log().Warn("Did not receive any response from the token endpoint.")
		return accessToken, ErrorTokenEndpointNoResponse
	}
	if tokenHttpResponse.StatusCode != 200 {
		logging.Log().Infof("Did not receive an ok from the token request. Was %s", logging.PrettyPrintObject(tokenHttpResponse))
		return accessToken, err
	}
	if tokenHttpResponse.Body == nil {
		logging.Log().Info("Received an empty body for the token request.")
		return accessToken, err
	}

	var tokenResponse TokenResponse

	err = json.NewDecoder(tokenHttpResponse.Body).Decode(&tokenResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the token response.")
		return accessToken, err
	}
	return tokenResponse.AccessToken, err
}

type TokenResponse struct {
	TokenType string `json:"token_type,omitempty"`

	// The lifetime in seconds of the access token
	ExpiresIn float32 `json:"expires_in,omitempty"`

	AccessToken string `json:"access_token,omitempty"`

	// The scope of the access token
	Scope string `json:"scope,omitempty"`
	// ID Token value associated with the authenticated session. Presents client's identity. ID Token is issued in a JWS format. See also the \"ID Token\" schema definition.
	IdToken string `json:"id_token,omitempty"`
}
