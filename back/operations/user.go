package operations

import (
	"context"
	"crypto/rand"

	"github.com/fiware/vcbackend/ent"
	"github.com/fiware/vcbackend/ent/user"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	zlog "github.com/rs/zerolog/log"
)

// User represents the user model
// It implements the webauthn.User interface
type User struct {
	db          *ent.Client
	entuser     *ent.User
	id          string
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *User) Create(name string, displayName string) (*User, error) {

	u.id = randomString()
	u.name = name
	u.displayName = displayName

	u.entuser = u.db.User.Create().SetID(u.id).
		SetName(name).
		SetDisplayname(displayName).SaveX(context.Background())

	return u, nil
}

// GetUser returns a *User by the user's username
func (u *User) GetByName(name string) (*User, error) {

	entuser, err := u.db.User.Query().Where(user.Name(name)).Only(context.Background())
	if err != nil {
		return nil, err
	}

	u.id = entuser.ID
	u.name = entuser.Name
	u.displayName = entuser.Displayname
	u.entuser = entuser

	// Get the credentials
	u.WebAuthnCredentials()

	return u, nil

}

func (u *User) GetOrCreate(name string, displayName string) (*User, error) {
	var err error

	// Search for the user
	_, err = u.GetByName(name)

	if ent.IsNotFound(err) {
		// User was not found, create a new user
		return u.Create(name, displayName)
	} else {
		// Return the retrieved user, or an error
		return u, err
	}

}

// WebAuthnID returns the user's ID
func (u User) WebAuthnID() []byte {
	return []byte(u.id)
}

// WebAuthnName returns the user's username
func (u User) WebAuthnName() string {
	return u.name
}

// WebAuthnDisplayName returns the user's display name
func (u User) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnIcon is not (yet) implemented
func (u User) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
// func (u *User) AddCredential(cred webauthn.Credential) {
// 	if u.entuser == nil {
// 		zlog.Panic().Msg("User model not initialized")
// 	}

// 	u.db.WebauthnCredential.Create().
// 		SetID(string(cred.ID)).
// 		SetCredential(cred).
// 		SetUser(u.entuser).
// 		SaveX(context.Background())

// }

// WebAuthnCredentials returns credentials owned by the user
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return nil
	// if u.entuser == nil {
	// 	zlog.Panic().Msg("User model not initialized")
	// }

	// entCreds := u.db.User.QueryCredentials(u.entuser).AllX(context.Background())

	// u.credentials = make([]webauthn.Credential, len(entCreds))

	// for i, ec := range entCreds {
	// 	u.credentials[i] = ec.Credential
	// }

	// return u.credentials
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all a user's credentials
func (u *User) CredentialExcludeList() []protocol.CredentialDescriptor {
	if u.entuser == nil {
		zlog.Panic().Msg("User model not initialized")
	}

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

func randomString() string {
	buf := make([]byte, 10)
	rand.Read(buf)
	return string(buf)
}
