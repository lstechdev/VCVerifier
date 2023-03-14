package model

type Policy struct {
	Policy   string       `json:"policy"`
	Argument *TirArgument `json:"argument,omitempty"`
}

type TirArgument struct {
	RegistryAddress string `json:"registryAddress"`
}
