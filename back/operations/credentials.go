package operations

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
)

type EmployeeCredentialData struct {
	Jti                string `json:"jti,omitempty" yaml:"jti" mapstructure:"jti"`
	CredName           string `json:"cred_name,omitempty" mapstructure:"credName"`
	CredType           string `json:"cred_type,omitempty" mapstructure:"credType"`
	IssuerDID          string `json:"iss,omitempty" mapstructure:"issuerDID"`
	SubjectDID         string `json:"did,omitempty" mapstructure:"subjectDID"`
	Name               string `json:"name,omitempty" mapstructure:"name"`
	Given_name         string `json:"given_name,omitempty" mapstructure:"given_name"`
	Family_name        string `json:"family_name,omitempty" mapstructure:"family_name"`
	Preferred_username string `json:"preferred_username,omitempty" mapstructure:"preferred_username"`
	Email              string `json:"email,omitempty" mapstructure:"email"`
	Target             string `json:"target,omitempty"`
	Roles              string `json:"roles,omitempty"`
}

type RoleForTarget struct {
	Target string   `json:"target,omitempty"`
	Names  []string `json:"names,omitempty"`
}

func (m *Manager) ConvertToMap(credIn *EmployeeCredentialData) (map[string]any, error) {
	out := make(map[string]any)
	claims := make(map[string]any)

	claims["given_name"] = credIn.Given_name
	claims["family_name"] = credIn.Family_name
	claims["name"] = credIn.Name
	claims["preferred_username"] = credIn.Preferred_username
	claims["email"] = credIn.Email

	var roles = []RoleForTarget{}

	names := strings.Split(credIn.Roles, ",")
	role := RoleForTarget{
		Target: credIn.Target,
		Names:  names,
	}

	roles = append(roles, role)
	claims["roles"] = roles

	out["claims"] = claims

	out["issuerDID"] = credIn.IssuerDID
	out["credName"] = credIn.CredName
	out["credType"] = credIn.CredType
	out["subjectDID"] = credIn.SubjectDID

	return out, nil
}

func (m *Manager) CreateServiceCredential(credIn map[string]any) (string, []byte, error) {

	credIn["credName"] = "PacketDeliveryCredential"
	credIn["issuerDID"] = m.cfg.String("issuer.DID")

	// Check if the user is already registered. We use the email as a unique identifier
	usr, err := m.v.UserByID(credIn["email"].(string))
	if err != nil {
		return "", nil, fiber.NewError(fiber.StatusInternalServerError, "error searching for user")
	}

	// Create a new user if it does not exist yet, with a default password
	if usr == nil {
		userName := credIn["familyName"].(string) + ", " + credIn["firstName"].(string)
		usr, err = m.v.CreateNaturalPersonWithKey(credIn["email"].(string), userName, "ThePassword")
		if err != nil {
			return "", nil, fiber.NewError(fiber.StatusInternalServerError, "error creating new user")
		}
	}

	// // Get the first private key from the user
	// keys, err := m.v.PrivateKeysForUser(usr.ID)
	// if err != nil || len(keys) == 0 {
	// 	return "", nil, fiber.NewError(fiber.StatusInternalServerError, "error getting private keys for user")
	// }

	// pubKey, err := keys[0].GetPublicKey()
	// if err != nil || len(keys) == 0 {
	// 	return "", nil, fiber.NewError(fiber.StatusInternalServerError, "error getting public key for user")
	// }

	credIn["subjectDID"] = "did:key:" + usr.ID

	return m.v.CreateCredentialJWTFromMap(credIn)

}

type CredentialSummary struct {
	Id string `json:"id,omitempty"`
}

func (m *Manager) GetAllCredentials() ([]CredentialSummary, error) {
	rawCreds := m.v.GetAllCredentials()

	credentials := make([]CredentialSummary, len(rawCreds))

	for i, rawCred := range rawCreds {
		credentials[i].Id = rawCred.Id
	}

	return credentials, nil

}

func (m *Manager) GetCredential(credID string) (claims string, err error) {

	// Check if the credential already exists

	rawCred, err := m.v.Client.Credential.Get(context.Background(), credID)
	if err != nil {
		return "", err
	}

	// A JWT token is composed of 3 parts concatenated by dots (".")
	parts := strings.Split(string(rawCred.Raw), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token contains an invalid number of segments")
	}

	// Decode claims part from B64Url
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	// JSON Decode, decoding to Number instead of floats
	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	dec.UseNumber()

	var claimDecoded any
	err = dec.Decode(&claimDecoded)
	if err != nil {
		return "", err
	}

	out, err := json.MarshalIndent(claimDecoded, "", "  ")
	if err != nil {
		return "", err
	}

	return string(out), nil

}

func (m *Manager) GetCredentialLD(credID string) (claims string, err error) {

	// Check if the credential already exists

	rawCred, err := m.v.Client.Credential.Get(context.Background(), credID)
	if err != nil {
		return "", err
	}

	s := prettyFormatJSON(rawCred.Raw)

	return s, nil

}

func prettyFormatJSON(in []byte) string {
	decoded := &fiber.Map{}
	json.Unmarshal(in, decoded)
	out, _ := json.MarshalIndent(decoded, "", "  ")
	return string(out)
}
