package verifier

import (
	"reflect"
	"testing"
)

var exampleCredential = map[string]interface{}{
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
		"id":     "someId",
		"target": "did:ebsi:packetdelivery",
		"type":   "gx:compliance",
	},
}

func TestMapVerifiableCredential(t *testing.T) {
	type args struct {
		raw map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    VerifiableCredential
		wantErr bool
	}{
		{
			"ValidCertificate",
			args{exampleCredential},
			VerifiableCredential{
				Id: "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
				Types: []string{
					"VerifiableCredential",
					"CustomerCredential",
				},
				Raw: exampleCredential,
				CredentialSubject: CredentialSubject{
					Id:          "someId",
					SubjectType: "gx:compliance",
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MapVerifiableCredential(tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapVerifiableCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapVerifiableCredential() = %v, want %v", got, tt.want)
			}
		})
	}
}
