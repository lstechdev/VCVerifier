package verifier

import (
	"errors"
	"testing"

	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/gaiax"
)

type mockRegistryClient struct {
	returnValues []string
	err          error
}

func (mrc *mockRegistryClient) GetComplianceIssuers() ([]string, error) {
	return mrc.returnValues, mrc.err
}

func createConfig(defaultsEnabled, specific bool) *configModel.Verifier {
	conf := configModel.Verifier{PolicyConfig: configModel.Policies{configModel.PolicyMap{}, make(map[string]configModel.PolicyMap)}}
	if defaultsEnabled {
		conf.PolicyConfig.DefaultPolicies[gaiaxCompliancePolicy] = configModel.PolicyConfigParameters{"registryAddress": "test.com"}
	}
	if specific {
		conf.PolicyConfig.CredentialTypeSpecificPolicies["gx:compliance"] = configModel.PolicyMap{gaiaxCompliancePolicy: configModel.PolicyConfigParameters{"registryAddress": "test.com"}}
	}
	return &conf
}

func TestGaiaXRegistryVerificationService_VerifyVC(t *testing.T) {
	type fields struct {
		verifierConfig      *configModel.Verifier
		gaiaxRegistryClient gaiax.RegistryClient
	}
	tests := []struct {
		name                 string
		fields               fields
		verifiableCredential VerifiableCredential
		wantResult           bool
		wantErr              bool
	}{
		{
			"HappyPath",
			fields{
				verifierConfig:      createConfig(true, false),
				gaiaxRegistryClient: &mockRegistryClient{[]string{"someDid"}, nil},
			},
			VerifiableCredential{MappableVerifiableCredential{Issuer: "someDid"}, nil},
			true,
			false,
		},
		{
			"IssuerUnknown",
			fields{
				verifierConfig:      createConfig(true, false),
				gaiaxRegistryClient: &mockRegistryClient{[]string{"someDid"}, nil},
			},
			VerifiableCredential{MappableVerifiableCredential{Issuer: "someUnknownDid"}, nil},
			false,
			false,
		},
		{
			"RegistryIssue",
			fields{
				verifierConfig:      createConfig(true, false),
				gaiaxRegistryClient: &mockRegistryClient{[]string{}, errors.New("Registry failed")},
			},
			VerifiableCredential{MappableVerifiableCredential{Issuer: "someDid"}, nil},
			false,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := InitGaiaXRegistryVerificationService(tt.fields.verifierConfig)
			v.gaiaxRegistryClient = tt.fields.gaiaxRegistryClient

			gotResult, err := v.VerifyVC(tt.verifiableCredential, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("GaiaXRegistryVerificationService.VerifyVC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotResult != tt.wantResult {
				t.Errorf("GaiaXRegistryVerificationService.VerifyVC() = %v, want %v", gotResult, tt.wantResult)
			}
		})
	}
}
