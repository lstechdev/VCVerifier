package verifier

import (
	"encoding/base64"
	"encoding/json"

	"github.com/fiware/VCVerifier/logging"
	tir "github.com/fiware/VCVerifier/tir"
	"golang.org/x/exp/slices"
)

/**
*	The trusted participant verification service will validate the entry of a participant within the trusted list.
 */
type TrustedIssuerVerificationService struct {
	tirClient tir.TirClient
}

func (tpvs *TrustedIssuerVerificationService) VerifyVC(verifiableCredential VerifiableCredential, verificationContext VerificationContext) (result bool, err error) {

	logging.Log().Debugf("Verify trusted issuer for %s", logging.PrettyPrintObject(verifiableCredential))
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("Was not able to convert context. Err: %v", recErr)
			err = ErrorCannotConverContext
		}
	}()
	trustContext := verificationContext.(TrustRegistriesVerificationContext)
	if len(trustContext.GetTrustedIssuersLists()) == 0 {
		logging.Log().Debug("The verfication context does not specify a trusted issuers list, therefor we consider every issuer as trusted.")
		return true, err
	}
	exist, trustedIssuer, err := tpvs.tirClient.GetTrustedIssuer(trustContext.GetTrustedIssuersLists(), verifiableCredential.Issuer)

	if err != nil {
		logging.Log().Warnf("Was not able to verify trusted issuer. Err: %v", err)
		return false, err
	}
	if !exist {
		logging.Log().Warnf("Trusted issuer for %s does not exist in context %s.", logging.PrettyPrintObject(verifiableCredential), logging.PrettyPrintObject(verificationContext))
		return false, err
	}
	credentials, err := parseAttributes(trustedIssuer)
	if err != nil {
		logging.Log().Warnf("Was not able to parse the issuer %s. Err: %v", logging.PrettyPrintObject(trustedIssuer), err)
	}
	return verifyWithCredentialsConfig(verifiableCredential, credentials)
}

func verifyWithCredentialsConfig(verifiableCredential VerifiableCredential, credentials []tir.Credential) (result bool, err error) {

	credentialsConfigMap := map[string]tir.Credential{}
	allowedTypes := []string{}
	// format for better validation
	for _, credential := range credentials {
		allowedTypes = append(allowedTypes, credential.CredentialsType)
		credentialsConfigMap[credential.CredentialsType] = credential
	}
	// we initalize with true, since there is no case where types can be empty.
	var typeAllowed = true
	// initalize to true, since everything without a specific rule is considered to be allowed
	var subjectAllowed = true
	logging.Log().Debugf("Validate that the type %v is allowed by %v.", verifiableCredential.Types, allowedTypes)
	// validate that the type(s) is allowed
	for _, credentialType := range verifiableCredential.MappableVerifiableCredential.Types {
		typeAllowed = typeAllowed && slices.Contains(allowedTypes, credentialType)
		subjectAllowed = subjectAllowed && verifyForType(verifiableCredential.MappableVerifiableCredential.CredentialSubject, credentialsConfigMap[credentialType])
	}
	if !typeAllowed {
		logging.Log().Debugf("Credentials type %s is not allowed.", logging.PrettyPrintObject(verifiableCredential.Types))
		return false, err
	}
	if !subjectAllowed {
		logging.Log().Debugf("The subject contains forbidden claims or values: %s.", logging.PrettyPrintObject(verifiableCredential.CredentialSubject))
		return false, err
	}
	logging.Log().Debugf("Credential %s is allowed by the config %s.", logging.PrettyPrintObject(verifiableCredential), logging.PrettyPrintObject(credentials))
	return true, err
}

func verifyForType(subjectToVerfiy CredentialSubject, credentialConfig tir.Credential) (result bool) {
	for _, claim := range credentialConfig.Claims {
		claimValue, exists := subjectToVerfiy.Claims[claim.Name]
		if !exists {
			logging.Log().Debugf("Restricted claim %s is not part of the subject %s.", claim.Name, logging.PrettyPrintObject(subjectToVerfiy))
			continue
		}
		isAllowed := contains(claim.AllowedValues, claimValue)
		if !isAllowed {
			logging.Log().Debugf("The claim value %s is not allowed by the config %s.", logging.PrettyPrintObject(claimValue), logging.PrettyPrintObject(credentialConfig))
			return false
		}
	}
	logging.Log().Debugf("No forbidden claim found for subject %s. Checked config was %s.", logging.PrettyPrintObject(subjectToVerfiy), logging.PrettyPrintObject(credentialConfig))
	return true
}

/**
* Check if the given interface is contained. In order to avoid type issues(f.e. if numbers are parsed to different interfaces),
* we marshal and compare the json representation.
 */
func contains(interfaces []interface{}, interfaceToCheck interface{}) bool {
	jsonBytesToCheck, err := json.Marshal(interfaceToCheck)
	if err != nil {
		logging.Log().Warn("Was not able to marshal the interface.")
		return false
	}
	for _, i := range interfaces {
		jsonBytes, err := json.Marshal(i)
		if err != nil {
			logging.Log().Warn("Not able to marshal one of the intefaces.")
			continue
		}
		if slices.Compare(jsonBytes, jsonBytesToCheck) == 0 {
			return true
		}
	}
	logging.Log().Debugf("%s does not contain %s", logging.PrettyPrintObject(interfaces), logging.PrettyPrintObject(interfaceToCheck))

	return false
}

func parseAttributes(trustedIssuer tir.TrustedIssuer) (credentials []tir.Credential, err error) {
	credentials = []tir.Credential{}
	for _, attribute := range trustedIssuer.Attributes {
		parsedCredential, err := parseAttribute(attribute)
		if err != nil {
			logging.Log().Warnf("Was not able to parse attribute %s. Err: %v", logging.PrettyPrintObject(attribute), err)
			return credentials, err
		}
		credentials = append(credentials, parsedCredential)
	}
	return credentials, err
}

func parseAttribute(attribute tir.IssuerAttribute) (credential tir.Credential, err error) {
	decodedAttribute, err := base64.StdEncoding.DecodeString(attribute.Body)
	if err != nil {
		logging.Log().Warnf("The attribute body %s is not correctly base64 encoded. Err: %v", attribute.Body, err)
		return credential, err
	}
	err = json.Unmarshal(decodedAttribute, &credential)
	if err != nil {
		logging.Log().Warnf("Was not able to unmarshal the credential %s. Err: %v", attribute.Body, err)
	}
	return
}
