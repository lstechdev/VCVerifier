package tir

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bxcodec/httpcache"
	"github.com/fiware/VCVerifier/logging"
)

const ISSUERS_V4_PATH = "v4/issuers"
const ISSUERS_V3_PATH = "v3/issuers"

const DID_V4_Path = "v4/identifiers"

var ErrorTirNoResponse = errors.New("no_response_from_tir")
var ErrorTirEmptyResponse = errors.New("empty_response_from_tir")

type HttpClient interface {
	Get(url string) (resp *http.Response, err error)
	Do(req *http.Request) (*http.Response, error)
}

type TirClient interface {
	IsTrustedParticipant(tirEndpoints []string, did string) (trusted bool)
	GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error)
}

/**
* A client to retrieve infromation from EBSI-compatible TrustedIssuerRegistry APIs.
 */
type TirHttpClient struct {
	client HttpGetClient
}

/**
* A trusted issuer as defined by EBSI
 */
type TrustedIssuer struct {
	Did        string            `json:"did"`
	Attributes []IssuerAttribute `json:"attributes"`
}

/**
* Attribute of an issuer
 */
type IssuerAttribute struct {
	Hash       string `json:"hash"`
	Body       string `json:"body"`
	IssuerType string `json:"issuerType"`
	Tao        string `json:"tao"`
	RootTao    string `json:"rootTao"`
}

/**
* Configuration of a credentialType, its validity time and the claims allowed to be issued
 */
type Credential struct {
	ValidFor        TimeRange `json:"validFor"`
	CredentialsType string    `json:"credentialsType"`
	Claims          []Claim   `json:"claims"`
}

type TimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Claim struct {
	Name          string        `json:"name"`
	AllowedValues []interface{} `json:"allowedValues"`
}

func NewTirHttpClient(tokenProvider *TokenProvider) (client TirClient, err error) {

	httpClient := &http.Client{}
	_, err = httpcache.NewWithInmemoryCache(httpClient, true, time.Second*60)
	if err != nil {
		logging.Log().Errorf("Was not able to inject the cache to the client. Err: %v", err)
		return
	}
	var httpGetClient HttpGetClient
	if tokenProvider != nil {
		httpGetClient = AuthorizingHttpClient{httpClient: httpClient, tokenProvider: tokenProvider}
	} else {
		httpGetClient = NoAuthHttpClient{httpClient: httpClient}
	}

	return TirHttpClient{client: httpGetClient}, err
}

func (tc TirHttpClient) IsTrustedParticipant(tirEndpoints []string, did string) (trusted bool) {
	for _, tirEndpoint := range tirEndpoints {
		logging.Log().Debugf("Check if a participant %s is trusted through %s.", did, tirEndpoint)
		if tc.issuerExists(tirEndpoint, did) {
			logging.Log().Debugf("Issuer %s is a trusted participant via %s.", did, tirEndpoint)
			return true
		}
	}
	return false
}

func (tc TirHttpClient) GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error) {
	for _, tirEndpoint := range tirEndpoints {
		resp, err := tc.requestIssuer(tirEndpoint, did)
		if err != nil {
			logging.Log().Warnf("Was not able to get the issuer %s from %s because of err: %v.", did, tirEndpoint, err)
			continue
		}
		if resp.StatusCode != 200 {
			logging.Log().Debugf("Issuer %s is not known at %s.", did, tirEndpoint)
			continue
		}
		trustedIssuer, err := parseTirResponse(*resp)
		if err != nil {
			logging.Log().Warnf("Was not able to parse the response from tir %s for %s. Err: %v", tirEndpoint, did, err)
			continue
		}
		logging.Log().Debugf("Got issuer %s.", logging.PrettyPrintObject(trustedIssuer))
		return true, trustedIssuer, err
	}
	return false, trustedIssuer, err
}

func parseTirResponse(resp http.Response) (trustedIssuer TrustedIssuer, err error) {

	if resp.Body == nil {
		logging.Log().Info("Received an empty body from the tir.")
		return trustedIssuer, ErrorTirEmptyResponse
	}

	err = json.NewDecoder(resp.Body).Decode(&trustedIssuer)
	if err != nil {
		logging.Log().Warn("Was not able to decode the tir-response.")
		return trustedIssuer, err
	}
	return trustedIssuer, err
}

func (tc TirHttpClient) issuerExists(tirEndpoint string, did string) (trusted bool) {
	// in 2.1.0 the did-document was requested. However, this seems to be wrong, therefor we go back to the issuers check.
	// for future discussion, this part is left as a comment.
	// 	resp, err := tc.requestDidDocument(tirEndpoint, did)

	resp, err := tc.requestIssuer(tirEndpoint, did)
	if err != nil {
		return false
	}
	logging.Log().Debugf("Issuer %s response from %s is %v", did, tirEndpoint, resp.StatusCode)
	// if a 200 is returned, the issuer exists. We dont have to parse the whole response
	return resp.StatusCode == 200
}

func (tc TirHttpClient) requestIssuer(tirEndpoint string, did string) (response *http.Response, err error) {
	response, err = tc.requestIssuerWithVersion(tirEndpoint, getIssuerV4Url(did))
	if err != nil {
		logging.Log().Debugf("Got error %v", err)
		return tc.requestIssuerWithVersion(tirEndpoint, getIssuerV3Url(did))
	}
	if response.StatusCode != 200 {
		logging.Log().Debugf("Got status %v", response.StatusCode)
		return tc.requestIssuerWithVersion(tirEndpoint, getIssuerV3Url(did))
	}
	return response, err
}

// currently unused, did-registry has a different purpose.
func (tc TirHttpClient) requestDidDocument(tirEndpoint string, did string) (didDocument DIDDocument, err error) {

	client, err := NewClientWithResponses(tirEndpoint)
	if err != nil {
		return didDocument, fmt.Errorf("error while initiating client for requesting did %s from %s: %W", did, tirEndpoint, err)
	}
	timeoutContext, derefFunc := context.WithTimeout(context.Background(), time.Second*30)
	defer derefFunc()
	resp, err := client.GetDIDDocumentWithResponse(timeoutContext, did, nil)
	if err != nil {
		return didDocument, fmt.Errorf("error while requesting did %s from %s: %W", did, tirEndpoint, err)
	}
	if resp.StatusCode() != 200 {
		return didDocument, fmt.Errorf("unexpected status code %d while requesting did %s from %s", resp.StatusCode(), did, tirEndpoint)
	}

	if resp.JSON200 == nil {
		return didDocument, fmt.Errorf("answer did not include the did document for %s from %s: %v", did, tirEndpoint, resp)
	}
	return *resp.JSON200, nil
}

func (tc TirHttpClient) requestIssuerWithVersion(tirEndpoint string, didPath string) (response *http.Response, err error) {
	logging.Log().Debugf("Get issuer %s/%s.", tirEndpoint, didPath)
	logging.Log().Debugf("Client %v", tc.client)
	resp, err := tc.client.Get(tirEndpoint, didPath)
	if err != nil {
		logging.Log().Warnf("Was not able to get the issuer %s from %s. Err: %v", didPath, tirEndpoint, err)
		return resp, err
	}
	if resp == nil {
		logging.Log().Warnf("Was not able to get any response for issuer %s from %s.", didPath, tirEndpoint)
		return nil, ErrorTirNoResponse
	}
	logging.Log().Infof("Got response %v", resp)
	return resp, err
}

func getIssuerV4Url(did string) string {
	return ISSUERS_V4_PATH + "/" + did
}

func getIssuerV3Url(did string) string {
	return ISSUERS_V3_PATH + "/" + did

}
