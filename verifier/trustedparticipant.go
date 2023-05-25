package verifier

import (
	tir "github.com/fiware/VCVerifier/tir"
)

/**
*	The trusted participant verification service will validate the entry of a participant within the trusted list.
 */
type TrustedParticipantVerificationService struct {
	tirClient tir.TirClient
}

func (tpvs *TrustedParticipantVerificationService) VerifyVC(verifiableCredential VerifiableCredential, verificationContext VerificationContext) (result bool, err error) {
	trustContext := verificationContext.(TrustRegistriesVerificationContext)
	exist, trustedIssuer, err := tpvs.tirClient.GetTrustedIssuer(trustContext.GetTrustedParticipantLists(), verifiableCredential.Issuer)
	if err != nil {
		return false, err
	}
	if !exist {
		return false, err
	}
	trustedIssuer.Attributes
}
