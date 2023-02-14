package model

type Policy struct {
	Policy   string       `json:"policy"`
	Argument *TirArgument `json:"argument"`
}

type TirArgument struct {
	RegistryAddress string `json:"registryAddress"`
}
