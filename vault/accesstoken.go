package vault

import (
	"encoding/json"
	"fmt"

	"github.com/hesusruiz/vcutils/yaml"
	zlog "github.com/rs/zerolog/log"
)

// CreateAccessToken creates a JWT access token from the credential in serialized form,
// signed with the first private key associated to the issuer DID
func (v *Vault) CreateAccessToken(credData string, issuerDID string) (json.RawMessage, error) {

	// Return error if the issuerDID does not exist
	iss, err := v.UserByID(issuerDID)
	if err != nil {
		return nil, err
	}
	if iss == nil {
		return nil, fmt.Errorf("user does not exist")
	}

	// Get the first private key of the issuer to make the signature
	jwks, err := v.PrivateKeysForUser(issuerDID)
	if err != nil {
		return nil, err
	}

	// At this point, jwks has at least one key, get the first one
	privateJWK := jwks[0]

	// Parse the serialized credential into a struct
	data, err := yaml.ParseJson(credData)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return nil, err
	}

	jwt := map[string]any{"verifiableCredential": data.Data()}

	// Sign the credential data with the private key
	signedString, err := v.SignWithJWK(privateJWK, jwt)
	if err != nil {
		return nil, err
	}

	_, err = v.CredentialFromJWT(signedString)
	if err != nil {
		zlog.Logger.Error().Err(err).Send()
		return nil, err
	}

	return []byte(signedString), nil

}
