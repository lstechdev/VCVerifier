package verifier

import (
	tir "github.com/fiware/VCVerifier/tir"
)

/**
*	The trusted participant verification service will validate the entry of a participant within the trusted list.
 */
type TrustedIssuerVerificationService struct {
	tirClient tir.TirClient
}

func (tpvs *TrustedIssuerVerificationService) VerifyVC(verifiableCredential VerifiableCredential, verificationContext VerificationContext) (result bool, err error) {
	trustContext := verificationContext.(TrustRegistriesVerificationContext)
 tpvs.tirClient.GetTrustedIssuer(trustContext.GetTrustedParticipantLists(), verifiableCredential.Issuer), nil
}
