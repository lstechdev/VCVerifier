package model

type VerifiableCredential struct {
	Context           []string               `json:"@context,omitempty"`
	Id                string                 `json:"id,omitempty"`
	Type              []string               `json:"type,omitempty"`
	Issuer            string                 `json:"issuer,omitempty"`
	IssuanceDate      string                 `json:"issuanceDate,omitempty"`
	ValidFrom         string                 `json:"validFrom,omitempty"`
	ExpirationDate    string                 `json:"expirationDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject,omitempty"`
	Proof             map[string]interface{} `json:"proof"`
}

type Policy struct {
	Policy   string       `json:"policy"`
	Argument *TirArgument `json:"argument"`
}

type TirArgument struct {
	RegistryAddress string `json:"registryAddress"`
}
