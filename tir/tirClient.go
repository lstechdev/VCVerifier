package tir

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bxcodec/httpcache"
	"github.com/fiware/VCVerifier/logging"
)

const ISSUERS_PATH = "v4/issuers"

var ErrorTirNoResponse = errors.New("no_response_from_tir")
var ErrorTirEmptyResponse = errors.New("empty_response_from_tir")

type HttpClient interface {
	Get(url string) (resp *http.Response, err error)
}

type TirClient interface {
	IsTrustedParticipant(tirEndpoints []string, did string) (trusted bool)
	GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer TrustedIssuer, err error)
}

/**
* A client to retrieve infromation from EBSI-compatible TrustedIssuerRegistry APIs.
 */
type TirHttpClient struct {
	client HttpClient
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

func NewTirHttpClient() (client TirClient, err error) {

	httpClient := &http.Client{}
	_, err = httpcache.NewWithInmemoryCache(httpClient, true, time.Second*60)
	if err != nil {
		logging.Log().Errorf("Was not able to inject the cach to the client. Err: %v", err)
		return
	}
	return TirHttpClient{httpClient}, err
}

func (tc TirHttpClient) IsTrustedParticipant(tirEndpoints []string, did string) (trusted bool) {

	for _, tirEndpoint := range tirEndpoints {
		logging.Log().Debugf("Check if a participant %s is trusted through %s.", did, tirEndpoint)
		if tc.issuerExists(getIssuerUrl(tirEndpoint), did) {
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
	resp, err := tc.requestIssuer(tirEndpoint, did)
	if err != nil {
		return false
	}
	// if a 200 is returned, the issuer exists. We dont have to parse the whole response
	return resp.StatusCode == 200
}

func (tc TirHttpClient) requestIssuer(tirEndpoint string, did string) (response *http.Response, err error) {
	resp, err := tc.client.Get(tirEndpoint + "/" + did)
	if err != nil {
		logging.Log().Warnf("Was not able to get the issuer %s from %s. Err: %v", did, tirEndpoint, err)
		return resp, err
	}
	if resp == nil {
		logging.Log().Warnf("Was not able to get any response for issuer %s from %s.", did, tirEndpoint)
		return nil, ErrorTirNoResponse
	}
	return resp, err
}

func getIssuerUrl(tirEndpoint string) string {
	if strings.HasSuffix(tirEndpoint, "/") {
		return tirEndpoint + ISSUERS_PATH
	} else {
		return tirEndpoint + "/" + ISSUERS_PATH
	}
}
