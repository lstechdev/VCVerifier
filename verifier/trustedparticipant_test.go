package verifier

import (
	"testing"

	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
)

type mockTirClient struct {
	expectedExists bool
	expectedIssuer tir.TrustedIssuer
	expectedError  error
}

func (mtc mockTirClient) IsTrustedParticipant(tirEndpoints []string, did string) (trusted bool) {
	return mtc.expectedExists
}

func (mtc mockTirClient) GetTrustedIssuer(tirEndpoints []string, did string) (exists bool, trustedIssuer tir.TrustedIssuer, err error) {
	return mtc.expectedExists, mtc.expectedIssuer, mtc.expectedError
}

func TestVerifyVC_Participant(t *testing.T) {

	type test struct {
		testName            string
		credentialToVerifiy VerifiableCredential
		verificationContext VerificationContext
		tirResponse         bool
		expectedResult      bool
	}

	tests := []test{
		{testName: "A credential issued by a registerd issuer should be successfully validated.", credentialToVerifiy: VerifiableCredential{raw: map[string]interface{}{"issuer": "did:web:trusted-issuer.org"}}, verificationContext: TrustRegistriesVerificationContext{trustedParticipantsRegistries: map[string][]string{"someType": []string{"http://my-trust-registry.org"}}}, tirResponse: true, expectedResult: true},
		{testName: "A credential issued by a not-registerd issuer should be rejected.", credentialToVerifiy: VerifiableCredential{raw: map[string]interface{}{"issuer": "did:web:trusted-issuer.org"}}, verificationContext: TrustRegistriesVerificationContext{trustedParticipantsRegistries: map[string][]string{"someType": []string{"http://my-trust-registry.org"}}}, tirResponse: false, expectedResult: false},
		{testName: "If no registry is configured, the credential should be accepted.", credentialToVerifiy: VerifiableCredential{raw: map[string]interface{}{"issuer": "did:web:trusted-issuer.org"}}, verificationContext: TrustRegistriesVerificationContext{trustedParticipantsRegistries: map[string][]string{}}, expectedResult: true},
		{testName: "If no registry is configured, the credential should be accepted.", credentialToVerifiy: VerifiableCredential{raw: map[string]interface{}{"issuer": "did:web:trusted-issuer.org"}}, verificationContext: TrustRegistriesVerificationContext{trustedParticipantsRegistries: map[string][]string{"VerifiableCredential": []string{}}}, expectedResult: true},
		{testName: "If an invalid context is received, the credential should be rejected.", credentialToVerifiy: VerifiableCredential{raw: map[string]interface{}{"issuer": "did:web:trusted-issuer.org"}}, verificationContext: "No-Context", tirResponse: false, expectedResult: false},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			logging.Log().Info("TestVerifyVC +++++++++++++++++ Running test: ", tc.testName)

			trustedParticipantVerificationService := TrustedParticipantVerificationService{mockTirClient{tc.tirResponse, tir.TrustedIssuer{}, nil}}
			result, _ := trustedParticipantVerificationService.VerifyVC(tc.credentialToVerifiy, tc.verificationContext)
			if result != tc.expectedResult {
				t.Errorf("%s - Expected result %v but was %v.", tc.testName, tc.expectedResult, result)
				return
			}
		})
	}
}
