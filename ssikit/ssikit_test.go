package ssikit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"wistefan/VCVerifier/logging"
)

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

	tests := []test{

		{"A verifiable credential should be successfully validated.", []Policy{{"MyPolicy", nil}}, getVC("vc"), getVRResponse(verificationResponse{Valid: true}), nil, true, nil},
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
