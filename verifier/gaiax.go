package verifier

import (
	"fmt"

	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/gaiax"
	"golang.org/x/exp/slices"

	logging "github.com/fiware/VCVerifier/logging"
)

const gaiaxCompliancePolicy = "GaiaXComplianceIssuer"
const registryUrlPropertyName = "registryAddress"

type GaiaXRegistryVerifier struct {
	validateAll               bool
	credentialTypesToValidate []string
	// client for gaiax registry connection
	gaiaxRegistryClient gaiax.RegistryClient
}

func InitGaiaXRegistryVerifier(verifierConfig *configModel.Verifier) GaiaXRegistryVerifier {
	var url string
	verifier := GaiaXRegistryVerifier{credentialTypesToValidate: []string{}}

	for policyName, arguments := range verifierConfig.PolicyConfig.DefaultPolicies {
		if policyName == gaiaxCompliancePolicy {
			url = fmt.Sprintf("%v", arguments[registryUrlPropertyName])
			verifier.validateAll = true
		}
	}
	for credentialType, policies := range verifierConfig.PolicyConfig.CredentialTypeSpecificPolicies {
		for policyName, arguments := range policies {
			if policyName == gaiaxCompliancePolicy {
				url = fmt.Sprintf("%v", arguments[registryUrlPropertyName])
				verifier.credentialTypesToValidate = append(verifier.credentialTypesToValidate, credentialType)
			}
		}
	}
	if len(url) > 0 {
		verifier.gaiaxRegistryClient = gaiax.InitGaiaXRegistryVerifier(url)
	}
	return verifier
}

func (v *GaiaXRegistryVerifier) VerifyVC(verifiableCredential VerifiableCredential) (result bool, err error) {
	if v.validateAll || slices.Contains(v.credentialTypesToValidate, verifiableCredential.GetCredentialType()) {
		issuerDids, err := v.gaiaxRegistryClient.GetComplianceIssuers()
		if err != nil {
			return false, err
		}
		if slices.Contains(issuerDids, verifiableCredential.GetIssuer()) {
			logging.Log().Info("Credential was issued by trusted issuer")
			return true, nil
		} else {
			logging.Log().Warnf("Failed to verify credential %s. Issuer was not in trusted issuer list", logging.PrettyPrintObject(verifiableCredential))
			return false, nil
		}
	}
	// No need to validate
	return true, nil
}
