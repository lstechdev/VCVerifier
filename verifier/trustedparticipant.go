package verifier

import (
	"errors"

	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
)

var ErrorCannotConverContext = errors.New("cannot_convert_context")

/**
*	The trusted participant verification service will validate the entry of a participant within the trusted list.
 */
type TrustedParticipantVerificationService struct {
	tirClient tir.TirClient
}

func (tpvs *TrustedParticipantVerificationService) VerifyVC(verifiableCredential VerifiableCredential, verificationContext VerificationContext) (result bool, err error) {

	logging.Log().Debugf("Verify trusted participant for %s", logging.PrettyPrintObject(verifiableCredential))
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("Was not able to convert context. Err: %v", recErr)
			err = ErrorCannotConverContext
		}
	}()
	trustContext := verificationContext.(TrustRegistriesVerificationContext)
	if len(trustContext.trustedParticipantsRegistries) == 0 {
		logging.Log().Debug("The verfication context does not specify a trusted issuers registry, therefor we consider every participant as trusted.")
		return true, err
	}
	// FIXME Can we assume that if we have a VC with multiple types, its enough to check for only one type?
	return tpvs.tirClient.IsTrustedParticipant(getFirstElementOfMap(trustContext.GetTrustedParticipantLists()), verifiableCredential.Issuer), err
}

func getFirstElementOfMap(slices map[string][]string) []string{
	for _, value := range slices {
		return value
	}
	return []string{}
}
