package verifier

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/did-go/doc/did"
	"github.com/trustbloc/did-go/method/jwk"
	"github.com/trustbloc/did-go/method/key"
	"github.com/trustbloc/did-go/method/web"
	"github.com/trustbloc/did-go/vdr"
	"github.com/trustbloc/did-go/vdr/api"
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

type VDR struct{}

func (v *VDR) Accept(method string, opts ...api.DIDMethodOption) bool {
	return method == "web"
}

// Update did doc.
func (v *VDR) Update(didDoc *did.Doc, opts ...api.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Deactivate did doc.
func (v *VDR) Deactivate(did string, opts ...api.DIDMethodOption) error {
	return fmt.Errorf("not supported")
}

// Close method of the VDR interface.
func (v *VDR) Close() error {
	return nil
}

// Read resolves a did:web did.
func (v *VDR) Read(didID string, opts ...api.DIDMethodOption) (*did.DocResolution, error) {
	httpClient := &http.Client{}

	didOpts := &api.DIDMethodOpts{Values: make(map[string]interface{})}
	// Apply options
	for _, opt := range opts {
		opt(didOpts)
	}

	address, _, err := parseDIDWeb(didID, false)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> could not parse did:web did --> %w", err)
	}

	resp, err := httpClient.Get(address)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> http request unsuccessful --> %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http server returned status code [%d]", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> error reading http response body: %s --> %w", body, err)
	}

	doc, err := did.ParseDocument(body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> error parsing did doc --> %w", err)
	}

	return &did.DocResolution{DIDDocument: doc}, nil
}

func parseDIDWeb(id string, useHTTP bool) (string, string, error) {
	var address, host string

	parsedDID, err := did.Parse(id)
	if err != nil {
		return address, host, fmt.Errorf("invalid did, does not conform to generic did standard --> %w", err)
	}

	pathComponents := strings.Split(parsedDID.MethodSpecificID, ":")

	pathComponents[0], err = url.QueryUnescape(pathComponents[0])
	if err != nil {
		return address, host, fmt.Errorf("error parsing did:web did")
	}

	host = strings.Split(pathComponents[0], ":")[0]

	protocol := "https://"
	if useHTTP {
		protocol = "http://"
	}

	switch len(pathComponents) {
	case 1:
		address = protocol + pathComponents[0] + defaultPath
	default:
		address = protocol + strings.Join(pathComponents, "/") + documentPath
	}

	return address, host, nil
}

func (tbv TrustBlocVerifier) VerifyVC(verifiableCredential *verifiable.Credential, verificationContext VerificationContext) (result bool, err error) {

	err = verifiableCredential.ValidateCredential()
	if err != nil {
		logging.Log().Info("Credential is invalid.")
		return false, err
	}
	return true, err
}

/**
func verify(jwtCredential string, verificationMethod did.VerificationMethod) (result bool, err error) {

	jwtParser := jwt.NewParser()
	if verificationMethod.JSONWebKey() != nil {
		jwtParser.Parse(jwtCredential, func(t *jwt.Token) (interface{}, error) {
			return th.GetKeyFromToken(t)
		})
	}
}

func getKey(t *jwt.Token) (key interface{}, err error) {
	registry := vdr.New()
	issuer, err := t.Claims.GetIssuer()
	if err != nil {
		logging.Log().Infof("No issuer claim configured. Err: %v", err)
	}
	kid, ok := t.Header["kid"]
	if !ok {
		logging.Log().Warnf("There is no kid configured inside the Jwt %s.", logging.PrettyPrintObject(t))
		return nil, ErrorNoKID
	}
	isAbsolute, extractedDid, extractedKid := isAbsoluteDid(kid.(string))
	if isAbsolute {
		issuer = extractedDid
	}
	didDocument, err := registry.Resolve(issuer)
	if err != nil {
		logging.Log().Warnf("Was not able to resolve the issuer %s.", issuer)
		return false, ErrorUnresolvableDid
	}
	var verificationMethod did.VerificationMethod
	for _, vm := range didDocument.DIDDocument.VerificationMethod {
		if extractedKid == "" {
			verificationMethod = vm
			break
		} else if extractedKid == vm.ID {
			verificationMethod = vm
			break
		}
	}
	if verificationMethod.ID == "" {
		return nil, ErrorNoVerificationKey
	}
	keyBytes, keyType, keyCurve, err := vmparse.VMToBytesTypeCrv(&verificationMethod)
	if err != nil {
		logging.Log().Warnf("Was not able to parse key from issuer %s for verification method %s. Err: %s", issuer, verificationMethod.ID, err)
		return nil, err
	}
	switch keyType {
	case kms.ED25519Type:
		var ed25519publicKey ed25519.PublicKey
		ed25519publicKey = keyBytes
		return ed25519publicKey, err
	case kms.RSAPS256Type:
		rsa.PublicKey
	}

}
*/

func isAbsoluteDid(kid string) (result bool, did string, extractedKid string) {
	parts := strings.Split(kid, ":")
	if len(parts) < 3 {
		return false, did, extractedKid
	}
	if parts[0] != "did" {
		return false, did, extractedKid
	}
	keyFragementIndex := strings.Index(kid, "#")
	if keyFragementIndex == -1 {
		return true, kid, extractedKid
	} else {
		return true, kid[0:keyFragementIndex], kid[keyFragementIndex+1 : len(kid)]
	}

}
