package verifier

import "github.com/mitchellh/mapstructure"

// Subset of the structure of a Verifiable Credential
type VerifiableCredential struct {
	Id                string            `mapstructure:"id"`
	Types             []string          `mapstructure:"type"`
	Issuer            string            `mapstructure:"issuer"`
	CredentialSubject CredentialSubject `mapstructure:"credentialSubject"`
	// The unaltered complete credential
	Raw map[string]interface{}
}

// Subset of the structure of a CredentialSubject inside a Verifiable Credential
type CredentialSubject struct {
	Id          string `mapstructure:"id"`
	SubjectType string `mapstructure:"type"`
}

func (vc VerifiableCredential) GetCredentialType() string {
	return vc.CredentialSubject.SubjectType
}

func (vc VerifiableCredential) GetRawData() map[string]interface{} {
	return vc.Raw
}

func (vc VerifiableCredential) GetIssuer() string {
	return vc.Issuer
}

func MapVerifiableCredential(raw map[string]interface{}) (VerifiableCredential, error) {
	var data VerifiableCredential
	config := &mapstructure.DecoderConfig{
		ErrorUnused: false,
		Result:      &data,
	}
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return VerifiableCredential{}, err
	}
	if err := decoder.Decode(raw); err != nil {
		return VerifiableCredential{}, err
	}
	data.Raw = raw
	return data, nil
}
