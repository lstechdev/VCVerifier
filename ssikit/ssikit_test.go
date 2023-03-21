package ssikit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	configModel "wistefan/VCVerifier/config"
	"wistefan/VCVerifier/logging"
)

func TestNewSSIKitClient(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})
	type test struct {
		testName      string
		testConfig    configModel.SSIKit
		expectedError error
	}

	tests := []test{
		{"If a valid config is provided, a client should be returned.", configModel.SSIKit{AuditorURL: "http://my-walt.org/auditor"}, nil},
		{"If no auditor is configured, an error should be returned.", configModel.SSIKit{}, ErrorNoAuditorConfigured},
	}

	for _, tc := range tests {

		logging.Log().Info("TestNewSSIKitClient +++++++++++++++++ Running test: ", tc.testName)

		client, err := NewSSIKitClient(&tc.testConfig)
		if tc.expectedError != err {
			t.Errorf("%s - Expected error %v but was %v.", tc.testName, tc.expectedError, err)
		}
		if tc.expectedError != nil {
			continue
		}

		if client == nil {
			t.Errorf("%s - A new client should have been created.", tc.testName)
		}
	}

}

func TestVerifyVC(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName       string
		testPolicies   []Policy
		testVC         map[string]interface{}
		ssiKitResponse *http.Response
		ssiKitError    error
		expectedResult bool
		expectedError  error
	}

	waltIdError := errors.New("walt_failure")

	tests := []test{

		{"A verifiable credential should be successfully validated.", []Policy{{"MyPolicy", nil}}, getVC("vc"), getVRResponse(verificationResponse{Valid: true}), nil, true, nil},
		{"If walt responds an error, the validation should fail.", []Policy{{"MyPolicy", nil}}, getVC("vc"), nil, waltIdError, false, waltIdError},
		{"If walt does not respond, the validation should fail.", []Policy{{"MyPolicy", nil}}, getVC("vc"), nil, nil, false, ErrorSSIKitNoResponse},
		{"If walt does not respond ok, the validation should fail.", []Policy{{"MyPolicy", nil}}, getVC("vc"), &http.Response{StatusCode: 204}, nil, false, nil},
		{"If walt does not respond with a body, the validation should fail.", []Policy{{"MyPolicy", nil}}, getVC("vc"), &http.Response{StatusCode: 200}, nil, false, nil},
		{"If walt does not respond with a valid body, the validation should fail.", []Policy{{"MyPolicy", nil}}, getVC("vc"), getInvalidResponse(), nil, false, nil},
		{"If walt does respond that the VC is invalid, the validation should fail.", []Policy{{"MyPolicy", nil}}, getVC("vc"), getVRResponse(verificationResponse{Valid: false}), nil, false, nil},
	}

	for _, tc := range tests {

		logging.Log().Info("TestVerifyVC +++++++++++++++++ Running test: ", tc.testName)

		httpClient = mockHttpClient{tc.ssiKitError, tc.ssiKitResponse}
		ssiKitClient := SSIKitClient{auditorAddress: "http://auditor.org"}
		ssiKitClient.VerifyVC(tc.testPolicies, tc.testVC)
	}
}

func getVRResponse(vr verificationResponse) *http.Response {
	d, _ := json.Marshal(vr)
	return &http.Response{Status: "200 ok", StatusCode: 200, Body: io.NopCloser(bytes.NewReader(d))}
}

func getInvalidResponse() *http.Response {
	return &http.Response{Status: "200 ok", StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte("something")))}

}

type mockHttpClient struct {
	err      error
	response *http.Response
}

func (mhc mockHttpClient) Do(req *http.Request) (r *http.Response, err error) {
	return mhc.response, mhc.err
}

func (mhc mockHttpClient) PostForm(url string, data url.Values) (r *http.Response, err error) {
	// not used
	return
}

func getVC(id string) map[string]interface{} {
	return map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://happypets.fiware.io/2022/credentials/employee/v1",
		},
		"id": "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
		"type": []string{
			"VerifiableCredential",
			"CustomerCredential",
		},
		"issuer":         "did:key:verifier",
		"issuanceDate":   "2022-11-23T15:23:13Z",
		"validFrom":      "2022-11-23T15:23:13Z",
		"expirationDate": "2032-11-23T15:23:13Z",
		"credentialSubject": map[string]interface{}{
			"id":     id,
			"target": "did:ebsi:packetdelivery",
		},
	}
}
