package verifier

import "github.com/mitchellh/mapstructure"

type VerifiableCredential struct {
	id                string            `mapstructure:"id"`
	types             []string          `mapstructure:"type"`
	credentialSubject CredentialSubject `mapstructure:"credentialSubject"`
	raw               map[string]interface{}
}

type CredentialSubject struct {
	id          string `mapstructure:"id"`
	subjectType string `mapstructure:"type"`
}

func (vc VerifiableCredential) GetCredentialType() string {
	return vc.credentialSubject.subjectType
}

func (vc VerifiableCredential) GetRawData() map[string]interface{} {
	return vc.raw
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
	data.raw = raw
	return data, nil
}
