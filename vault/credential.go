package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"github.com/fiware/vcbackend/ent"
	"github.com/fiware/vcbackend/internal/jwk"
	"github.com/fiware/vcbackend/internal/jwt"
	"github.com/google/uuid"
	"github.com/hesusruiz/vcutils/yaml"
	zlog "github.com/rs/zerolog/log"
	"github.com/tidwall/gjson"
)

type CredentialData struct {
	Jti                string `json:"jti" yaml:"jti"`
	CredName           string `json:"cred_name"`
	IssuerDID          string `json:"iss"`
	SubjectDID         string `json:"did"`
	Name               string `json:"name"`
	Given_name         string `json:"given_name"`
	Family_name        string `json:"family_name"`
	Preferred_username string `json:"preferred_username"`
	Email              string `json:"email"`
}

var t *template.Template

func init() {

	t = template.Must(template.New("base").Funcs(sprig.TxtFuncMap()).ParseGlob("vault/templates/*.tpl"))

}

func (v *Vault) TestCred(credData *CredentialData) (rawJsonCred json.RawMessage, err error) {

	// Generate the id as a UUID
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	// Set the unique id in the credential
	credData.Jti = jti.String()

	// Generate the credential from the template
	var b bytes.Buffer
	err = t.ExecuteTemplate(&b, credData.CredName, credData)
	if err != nil {
		return nil, err
	}

	// The serialized credential
	rawJsonCred = b.Bytes()

	// Validate the generated JSON, just in case the template is malformed
	if !gjson.ValidBytes(b.Bytes()) {
		zlog.Error().Msg("Error validating JSON")
		return nil, nil
	}
	m, ok := gjson.ParseBytes(b.Bytes()).Value().(map[string]interface{})
	if !ok {
		return nil, nil
	}

	rj, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	zlog.Info().Msgf("Value: %T\n\n%v", rj, string(rj))

	// cc := make(map[string]any)

	return nil, nil

}

// CreateCredentialJWTFromMap receives a map with the hierarchical data of the credential and returns
// the id of a new credential and the raw JWT string representing the credential
func (v *Vault) CreateCredentialJWTFromMap(credmap map[string]any) (credID string, rawJSONCred json.RawMessage, err error) {

	credData := yaml.New(credmap)

	// Return error if the issuer does not exist
	issuer := credData.String("issuerDID")
	iss, err := v.UserByID(issuer)
	if err != nil {
		return "", nil, err
	}
	if iss == nil {
		return "", nil, fmt.Errorf("user does not exist")
	}

	// Get the private key of the issuer. If not specified, get the first one
	var privateJWK *jwk.JWK
	if keyID := credData.String("issuerKeyID"); len(keyID) > 0 {

		// KeyID specified, try to get it from the store
		privateJWK, err = v.PrivateKeyByID(keyID)
		if err != nil {
			return "", nil, err
		}

	} else {

		// KeyID was not specified, look for the first key of the user
		jwks, err := v.PrivateKeysForUser(issuer)
		if err != nil {
			return "", nil, err
		}

		// jwks has at least one key, get the first one
		privateJWK = jwks[0]
	}

	// Generate a credential ID (jti) if it was not specified in the input data
	if len(credData.String("jti")) == 0 {

		// Generate the id as a UUID
		jti, err := uuid.NewRandom()
		if err != nil {
			return "", nil, err
		}

		// Set the unique id in the credential
		credmap["jti"] = jti.String()

	}

	credentialID := credmap["jti"].(string)

	// Generate the credential from the template
	var b bytes.Buffer
	err = t.ExecuteTemplate(&b, credData.String("credName"), credmap)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return "", nil, err
	}

	// The serialized credential
	fmt.Println("**** Serialized Credential ****")
	rawJSONCred = b.Bytes()
	fmt.Printf("%v\n\n", string(rawJSONCred))
	fmt.Println("**** End Serialized Credential ****")

	// Parse the resulting byte string
	data, err := yaml.ParseYamlBytes(rawJSONCred)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return "", nil, err
	}

	// Sign the credential data with the private key
	signedString, err := v.SignWithJWK(privateJWK, data.Data())
	if err != nil {
		return "", nil, err
	}

	_, err = v.CredentialFromJWT(signedString)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return "", nil, err
	}

	// Store credential
	_, err = v.Client.Credential.Create().
		SetID(credentialID).
		SetRaw([]uint8(signedString)).
		Save(context.Background())
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return "", nil, err
	}

	return credentialID, []byte(signedString), nil

}

type CredRawData struct {
	Id      string `json:"id,omitempty"`
	Type    string `json:"type,omitempty"`
	Encoded string `json:"encoded,omitempty"`
}

func (v *Vault) GetAllCredentials() (creds []*CredRawData) {

	entCredentials, err := v.Client.Credential.Query().All(context.Background())
	if err != nil {
		return nil
	}

	credentials := make([]*CredRawData, len(entCredentials))

	for i, cred := range entCredentials {
		cr := &CredRawData{}
		cr.Id = cred.ID
		cr.Type = cred.Type
		cr.Encoded = string(cred.Raw)
		credentials[i] = cr
	}

	return credentials

}

func (v *Vault) CreateOrGetCredential(credData *CredentialData) (rawJsonCred json.RawMessage, err error) {

	// Check if the credential already exists
	cred, err := v.Client.Credential.Get(context.Background(), credData.Jti)
	if err == nil {
		// Credential found, just return it
		return cred.Raw, nil
	}
	if !ent.IsNotFound(err) {
		// Continue only if the error was that the credential was not found
		return nil, err
	}

	// Generate the credential from the template
	var b bytes.Buffer
	err = t.ExecuteTemplate(&b, credData.CredName, credData)
	if err != nil {
		return nil, err
	}

	// The serialized credential
	rawJsonCred = b.Bytes()

	// Store in DB
	_, err = v.Client.Credential.
		Create().
		SetID(credData.Jti).
		SetRaw(rawJsonCred).
		Save(context.Background())
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing credential")
		return nil, err
	}
	zlog.Info().Str("jti", credData.Jti).Msg("credential created")

	return rawJsonCred, nil

}

type CredentialDecoded struct {
	jwt.RegisteredClaims
	Other map[string]any
}

func (v *Vault) CredentialFromJWT(credSerialized string) (rawJsonCred json.RawMessage, err error) {

	cred := &CredentialDecoded{}

	// Parse the serialized string into the structure, no signature validation yet
	token, err := jwt.NewParser().ParseUnverified2(credSerialized, cred)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return nil, err
	}

	// // Enable for Debugging
	// zlog.Debug().Msg("Parsed Token")
	// if out, err := json.MarshalIndent(token, "", "   "); err == nil {
	// 	zlog.Debug().Msg(string(out))
	// }

	// Verify the signature
	err = v.VerifySignature(token.ToBeSignedString, token.Signature, token.Alg(), token.Kid())
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return nil, err
	}

	// Display the formatted JSON structure
	st := map[string]any{}
	json.Unmarshal(token.ClaimBytes, &st)
	if out, err := json.MarshalIndent(st, "", "   "); err == nil {
		zlog.Debug().Msg(string(out))
	}

	return nil, nil

}
