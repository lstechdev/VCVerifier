package verifier

import (
	"errors"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/did-go/method/web"
	"github.com/trustbloc/did-go/vdr"
	"github.com/trustbloc/vc-go/verifiable"
	"github.com/trustbloc/vc-go/vermethod"
)

var ErrorNoKID = errors.New("no_kid_provided")
var ErrorUnresolvableDid = errors.New("unresolvable_did")
var ErrorNoVerificationKey = errors.New("no_verification_key")

const RsaVerificationKey2018 = "RsaVerificationKey2018"
const Ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
const (
	defaultPath  = "/.well-known/did.json"
	documentPath = "/did.json"
)

type TrustBlocVerifier struct{}

type JWTVerfificationMethodResolver struct{}

func (jwtVMR JWTVerfificationMethodResolver) ResolveVerificationMethod(verificationMethod string, expectedProofIssuer string) (*vermethod.VerificationMethod, error) {
	registry := vdr.New(vdr.WithVDR(web.New()), vdr.WithVDR(key.New()), vdr.WithVDR(jwk.New()))
	didDocument, err := registry.Resolve(expectedProofIssuer)
	if err != nil {
		logging.Log().Warnf("Was not able to resolve the issuer %s.", expectedProofIssuer)
		return nil, ErrorUnresolvableDid
	}
	for _, vm := range didDocument.DIDDocument.VerificationMethod {
		if vm.ID == verificationMethod {
			var vermethod = vermethod.VerificationMethod{Type: vm.Type, Value: vm.Value, JWK: vm.JSONWebKey()}
			return &vermethod, err
		}
	}
	return nil, ErrorNoVerificationKey
}

func (tbv TrustBlocVerifier) VerifyVC(verifiableCredential *verifiable.Credential, verificationContext VerificationContext) (result bool, err error) {

	err = verifiableCredential.ValidateCredential()
	if err != nil {
		logging.Log().Info("Credential is invalid.")
		return false, err
	}
	return true, err
}
