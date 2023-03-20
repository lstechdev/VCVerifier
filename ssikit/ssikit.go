package ssikit

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	configModel "wistefan/VCVerifier/config"
	"wistefan/VCVerifier/logging"

	client "github.com/fiware/dsba-pdp/http"
)

const verificationPath = "/v1/verify"

// configuration object for the ssikit client connection(s)
type SSIKitClient struct {
	auditorAddress string
}

// Policy object as defined by waltId
type Policy struct {
	Policy   string       `json:"policy"`
	Argument *TirArgument `json:"argument,omitempty"`
}

// TrustedIssuerRegistry Policy Argument - has to be provided to waltId
type TirArgument struct {
	RegistryAddress string `json:"registryAddress"`
}

// request structure for validating VCs at waltId
type verificationRequest struct {
	Policies    []Policy                 `json:"policies"`
	Credentials []map[string]interface{} `json:"credentials"`
}

// result of the individual policy
type verificationResult struct {
	Valid         bool            `json:"valid"`
	PolicyResults map[string]bool `json:"policyResults"`
}

// response structure from the verification request
type verificationResponse struct {
	Valid   bool                 `json:"valid"`
	Results []verificationResult `json:"results"`
}

type SSIKit interface {
	VerifyVC(policies []Policy, verifiableCredential map[string]interface{}) (result bool, err error)
}

/**
*   Create a new SSIKit client from the configuration
**/
func NewSSIKitClient(config *configModel.SSIKit) (client *SSIKitClient, err error) {
	if config.AuditorURL == "" {
		return client, errors.New("no_auditor_configured")
	}
	return &SSIKitClient{config.AuditorURL}, err
}

/**
*   Verify the given credentials at the walt against the provided policies
**/
func (s *SSIKitClient) VerifyVC(policies []Policy, verifiableCredential map[string]interface{}) (result bool, err error) {

	logging.Log().Debugf("Verify credential %s", logging.PrettyPrintObject(verifiableCredential))
	auditorAddress := s.auditorAddress + verificationPath

	// prepare the request
	verificationRequest := verificationRequest{policies, []map[string]interface{}{verifiableCredential}}
	jsonBody, err := json.Marshal(verificationRequest)
	if err != nil {
		logging.Log().Warnf("Was not able to marshal verification request body. Err: %v", err)
		return false, err
	}
	verificationHttpRequest, err := http.NewRequest("POST", auditorAddress, bytes.NewReader(jsonBody))
	if err != nil {
		logging.Log().Warnf("Was not able to create verification request. Err: %v", err)
		return false, err
	}
	verificationHttpRequest.Header.Set("Content-Type", "application/json")
	verificationHttpRequest.Header.Set("accept", "application/json")
	verificationHttpResponse, err := client.HttpClient().Do(verificationHttpRequest)

	// evaluate the results
	if err != nil || verificationHttpResponse == nil {
		logging.Log().Warnf("Did not receive a valid verification response. Err: %v", err)
		return false, err
	}
	if verificationHttpResponse.StatusCode != 200 {
		logging.Log().Infof("Did not receive an ok from the verifier. Was %s", logging.PrettyPrintObject(verificationHttpResponse))
		return false, err
	}
	if verificationHttpResponse.Body == nil {
		logging.Log().Info("Received an empty body on the verification.")
		return false, err
	}
	var verficationResponse verificationResponse

	err = json.NewDecoder(verificationHttpResponse.Body).Decode(&verficationResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the  verification response.")
		return false, err
	}
	if verficationResponse.Valid {
		return true, err
	} else {
		logging.Log().Info("Verfication failed.")
		logging.Log().Debugf("Detailed result is %v", logging.PrettyPrintObject(verficationResponse))
		return false, err
	}
}
