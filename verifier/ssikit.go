package verifier

import (
	configModel "github.com/fiware/VCVerifier/config"
	"golang.org/x/exp/maps"

	"github.com/fiware/VCVerifier/ssikit"
)

/**
* The SsiKit verifier should concentrate on general verification at the credential level(e.g. check signature, expiry etc.). Even thought a TIR policy could
* be configured, its recommended to use the TrustedIssuersRegistryVerifer or TrustedIssuersListVerifier for that purpose.
 */
type SsiKitExternalVerificationService struct {
	policies                   PolicyMap
	credentialSpecificPolicies map[string]PolicyMap
	// client for connection waltId
	ssiKitClient ssikit.SSIKit
}

type PolicyMap map[string]ssikit.Policy

// checks if the policy should be handled by ssikit
func isPolicySupportedBySsiKit(policyName string) bool {
	return policyName != gaiaxCompliancePolicy
}

func InitSsiKitExternalVerificationService(verifierConfig *configModel.Verifier, ssiKitClient ssikit.SSIKit) (verifier SsiKitExternalVerificationService, err error) {
	defaultPolicies := PolicyMap{}
	for policyName, arguments := range verifierConfig.PolicyConfig.DefaultPolicies {
		if isPolicySupportedBySsiKit(policyName) {
			defaultPolicies[policyName] = ssikit.CreatePolicy(policyName, arguments)
		}
	}
	credentialSpecificPolicies := map[string]PolicyMap{}
	for i, j := range verifierConfig.PolicyConfig.CredentialTypeSpecificPolicies {
		credentialSpecificPolicies[i] = PolicyMap{}
		for policyName, arguments := range j {
			if isPolicySupportedBySsiKit(policyName) {
				defaultPolicies[policyName] = ssikit.CreatePolicy(policyName, arguments)
			}
		}
	}
	return SsiKitExternalVerificationService{defaultPolicies, credentialSpecificPolicies, ssiKitClient}, nil
}

func (v *SsiKitExternalVerificationService) VerifyVC(verifiableCredential VerifiableCredential, verificationContext VerificationContext) (result bool, err error) {
	usedPolicies := PolicyMap{}
	for name, policy := range v.policies {
		usedPolicies[name] = policy
	}
	if policies, ok := v.credentialSpecificPolicies[verifiableCredential.GetCredentialType()]; ok {
		for name, policy := range policies {
			usedPolicies[name] = policy
		}
	}
	return v.ssiKitClient.VerifyVC(maps.Values(usedPolicies), verifiableCredential.GetRawData())
}
