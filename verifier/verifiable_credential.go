package verifier

import (
	"reflect"

	"github.com/mitchellh/mapstructure"
)

// Subset of the structure of a Verifiable Credential
type VerifiableCredential struct {
	MappableVerifiableCredential
	raw map[string]interface{} // The unaltered complete credential
}

// TODO Issue fix to mapstructure to enable combination of "DecoderConfig.ErrorUnset" and an unmapped/untagged field
type MappableVerifiableCredential struct {
	Id                string            `mapstructure:"id"`
	Types             []string          `mapstructure:"type"`
	Issuer            string            `mapstructure:"issuer"`
	CredentialSubject CredentialSubject `mapstructure:"credentialSubject"`
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
	return vc.raw
}

func (vc VerifiableCredential) GetIssuer() string {
	return vc.Issuer
}

func MapVerifiableCredential(raw map[string]interface{}) (VerifiableCredential, error) {
	var data MappableVerifiableCredential

	credentialSubjectArrayDecoder := func(from, to reflect.Type, data interface{}) (interface{}, error) {
		if to != reflect.TypeOf((*CredentialSubject)(nil)).Elem() {
			return data, nil
		}
		if reflect.TypeOf(data).Kind() != reflect.Slice {
			return data, nil
		}

		return data.([]map[string]interface{})[0], nil
	}

	config := &mapstructure.DecoderConfig{
		ErrorUnused:          false,
		Result:               &data,
		ErrorUnset:           true,
		IgnoreUntaggedFields: true,
		DecodeHook:           credentialSubjectArrayDecoder,
	}
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return VerifiableCredential{}, err
	}
	if err := decoder.Decode(raw); err != nil {
		return VerifiableCredential{}, err
	}
	return VerifiableCredential{data, raw}, nil
}
