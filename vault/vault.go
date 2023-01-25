package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/fiware/vcbackend/ent"
	"github.com/fiware/vcbackend/ent/did"
	"github.com/fiware/vcbackend/ent/user"
	"github.com/fiware/vcbackend/internal/jwk"
	"github.com/fiware/vcbackend/internal/jwt"
	"github.com/hesusruiz/vcutils/yaml"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zlog.Logger = zlog.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zlog.Logger = zlog.With().Caller().Logger()
}

type Vault struct {
	Client *ent.Client
}

type Signable interface {
	SigningString() (string, error)
	Kid() string
}

var mutexForNew sync.Mutex

// Must is a helper that wraps a call to a function returning (*Vault, error)
// and panics if the error is non-nil. It is intended for use in program
// initialization where the starting process has to be aborted in case of error.
// Usage is like this:
//
//	var issuerVault = vault.Must(vault.New(cfg))
func Must(v *Vault, err error) *Vault {
	if err != nil {
		panic(err)
	}

	return v
}

// New opens or creates a repository storing users, keys and credentials
func New(cfg *yaml.YAML) (v *Vault, err error) {

	if cfg == nil {
		return nil, fmt.Errorf("no configuration received")
	}

	// Make sure only one thread performs initialization of the database,
	// including migrations
	mutexForNew.Lock()
	defer mutexForNew.Unlock()

	v = &Vault{}

	// Get the configured parameters for the database
	storeDriverName := cfg.String("store.driverName")
	storeDataSourceName := cfg.String("store.dataSourceName")

	// Open the database
	v.Client, err = ent.Open(storeDriverName, storeDataSourceName)
	if err != nil {
		zlog.Error().Err(err).Msg("failed opening database")
		return nil, err
	}

	// Run the auto migration tool.
	if err := v.Client.Schema.Create(context.Background()); err != nil {
		zlog.Error().Err(err).Str("dataSourceName", storeDataSourceName).Msg("failed creating schema resources")
		return nil, err
	}

	return v, nil
}

// NewFromDBClient uses an existing client connection for creating the storage object
func NewFromDBClient(entClient *ent.Client) (v *Vault) {

	v = &Vault{}
	v.Client = entClient

	return v
}

// CreateLegalPersonWithKey creates a user of type "issuer" and an associated private key for signing.
// For a single tenant issuer installation, it should be enough with a single Issuer.
// The function expects the IssuerDID (a unique identifier) and the name of the entity.
func (v *Vault) CreateLegalPersonWithKey(issuerDID string, name string, password string) (usr *ent.User, err error) {

	return v.CreateUserWithKey(issuerDID, name, "issuer", password)

}

func (v *Vault) CreateNaturalPersonWithKey(id string, name string, password string) (usr *ent.User, err error) {
	return v.CreateUserWithKey(id, name, "normal", password)
}

func (v *Vault) CreateUser(userid string, name string, usertype string, password string) (usr *ent.User, err error) {

	// Return an error if the user already exists
	usr, _ = v.Client.User.Get(context.Background(), userid)
	if usr != nil {
		return nil, fmt.Errorf("user already exists")
	}

	// Calculate the password to store
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		panic(err)
	}

	// Create new user of the specified type
	usr, err = v.Client.User.
		Create().
		SetID(userid).
		SetName(name).
		SetType(usertype).
		SetPassword(hashedPassword).
		Save(context.Background())
	if err != nil {
		return nil, err
	}

	zlog.Info().Str("id", userid).Str("name", name).Str("type", usertype).Msg("user created")

	return usr, nil

}

// CreateUserWithKeyX is like CreateUserWithKey but panics if there is an error
func (v *Vault) CreateUserWithKeyX(userid string, name string, usertype string, password string) (usr *ent.User, err error) {
	usr, err = v.CreateUserWithKey(userid, name, usertype, password)
	if err != nil {
		panic(err)
	}
	return usr, err
}

func (v *Vault) CreateUserWithKey(userid string, name string, usertype string, password string) (usr *ent.User, err error) {

	// Return an error if the user already exists
	usr, _ = v.Client.User.Get(context.Background(), userid)
	if usr != nil {
		return nil, fmt.Errorf("user already exists")
	}

	// Calculate the password to store
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		panic(err)
	}

	// Create new user of the specified type
	usr, err = v.Client.User.
		Create().
		SetID(userid).
		SetName(name).
		SetType(usertype).
		SetPassword(hashedPassword).
		Save(context.Background())
	if err != nil {
		return nil, err
	}

	// Create a new key and add it to the user
	_, err = v.NewKeyForUser(userid)
	if err != nil {
		return nil, err
	}

	zlog.Info().Str("id", userid).Str("name", name).Str("type", usertype).Msg("user created")

	return usr, nil

}

func (v *Vault) SetDIDForUser(userid string, did string) error {
	// Get the account
	usr, err := v.Client.User.Get(context.Background(), userid)
	if err != nil {
		zlog.Error().Err(err).Str("id", userid).Msg("error retrieving user")
		return err
	}

	// Do nothing if the DID already exists
	if len(v.Client.DID.Query().AllX(context.Background())) > 0 {
		zlog.Info().Msg("did already exists")
		return nil
	}

	// Add the DID to this user
	newDID, err := v.Client.DID.Create().SetID(did).Save(context.Background())
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing DID")
		return err
	}

	// Update the user record to point to this key
	_, err = usr.Update().AddDids(newDID).Save(context.Background())

	return err

}

func (v *Vault) GetDIDForUser(userid string) (string, error) {
	return v.Client.DID.Query().Where(did.HasUserWith(user.ID(userid))).FirstID(context.Background())
}

func (v *Vault) NewKeyForUser(userid string) (*ent.PrivateKey, error) {

	// Get the account
	usr, err := v.Client.User.Get(context.Background(), userid)
	if err != nil {
		return nil, err
	}

	// Create a new private key, of the preferred type
	privKey, err := jwk.NewECDSA()
	if err != nil {
		zlog.Error().Err(err).Msg("failed creating new native ECDSA key")
		return nil, err
	}

	// Convert to JSON-JWK
	asJSON, err := privKey.AsJSON()
	if err != nil {
		zlog.Error().Err(err).Msg("failed converting key to json")
		return nil, err
	}

	// Store in private keys table
	kid := privKey.GetKid()
	dbKey, err := v.Client.PrivateKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		SetUser(usr).
		Save(context.Background())
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing key")
		return nil, err
	}
	zlog.Info().Str("kid", kid).Msg("key created")

	// Update the user record to point to this key
	usr.Update().AddKeys(dbKey).Save(context.Background())

	// Store the public part of the key in the public key table, to be used for verification
	pubKey := privKey.PublicJWKKey()
	// Convert to JSON-JWK
	asJSON, err = pubKey.AsJSON()
	if err != nil {
		zlog.Error().Err(err).Msg("failed converting public key to json")
		return nil, err
	}

	_, err = v.Client.PublicKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		Save(context.Background())
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing public key")
		return nil, err
	}

	zlog.Info().Str("name", userid).Msg("user updated")

	return dbKey, nil

}

func (v *Vault) AddKeyToUser(userid string, privKey *jwk.JWK) (*ent.PrivateKey, error) {

	// Get the account
	usr, err := v.Client.User.Get(context.Background(), userid)
	if err != nil {
		return nil, err
	}

	// Convert to JSON-JWK
	asJSON, err := privKey.AsJSON()
	if err != nil {
		zlog.Error().Err(err).Msg("failed converting key to json")
		return nil, err
	}

	// Store in private keys table
	kid := privKey.GetKid()
	dbKey, err := v.Client.PrivateKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		SetUser(usr).
		Save(context.Background())
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing key")
		return nil, err
	}
	zlog.Info().Str("kid", kid).Msg("key created")

	// Update the user record to point to this key
	usr.Update().AddKeys(dbKey).Save(context.Background())

	// Store the public part of the key in the public key table, to be used for verification
	pubKey := privKey.PublicJWKKey()
	// Convert to JSON-JWK
	asJSON, err = pubKey.AsJSON()
	if err != nil {
		zlog.Error().Err(err).Msg("failed converting public key to json")
		return nil, err
	}

	_, err = v.Client.PublicKey.
		Create().
		SetID(kid).
		SetKty("EC").
		SetJwk(asJSON).
		Save(context.Background())
	if err != nil {
		zlog.Error().Err(err).Msg("failed storing public key")
		return nil, err
	}

	zlog.Info().Str("name", userid).Msg("user updated")

	return dbKey, nil

}

// UserByID returns either a user or nil if not found, in the absence of any other error
func (v *Vault) UserByID(id string) (usr *ent.User, err error) {

	// Retrieve user by ID
	usr, err = v.Client.User.Get(context.Background(), id)

	// Log if the error is NotFound
	if ent.IsNotFound(err) {
		zlog.Debug().Err(err).Str("name", id).Msg("user not found")
		return nil, nil
	}

	if err != nil {
		zlog.Error().Err(err).Str("name", id).Msg("failed querying user")
		return nil, fmt.Errorf("failed querying user: %w", err)
	}
	zlog.Info().Str("name", id).Msg("user retrieved")
	return usr, nil

}

// PrivateKeysForUser returns all the private keys belonging to the userid
func (v *Vault) PrivateKeysForUser(userid string) (keys []*jwk.JWK, err error) {

	// Return an error if the user does not exist
	usr, err := v.UserByID(userid)
	if err != nil {
		zlog.Error().Err(err).Str("id", userid).Send()
		return nil, err
	}

	// Get all the keys
	entKeys, err := usr.QueryKeys().All(context.Background())
	if err != nil {
		zlog.Error().Err(err).Str("id", userid).Send()
		return nil, err
	}

	// Convert the keys to the JKW format
	keys = make([]*jwk.JWK, len(entKeys))

	for i, k := range entKeys {
		jwkKey, err := jwk.NewFromBytes(k.Jwk)
		if err != nil {
			continue
		}
		keys[i] = jwkKey
	}

	// Return an error if no keys were found
	if len(keys) == 0 {
		return nil, fmt.Errorf("the user has no private keys")
	}

	return keys, nil
}

// PublicKeysForUser returns all the public keys belonging to the userid
func (v *Vault) PublicKeysForUser(userid string) (keys []*jwk.JWK, err error) {

	// Return an error if the user does not exist
	usr, err := v.UserByID(userid)
	if err != nil {
		zlog.Error().Err(err).Str("id", userid).Send()
		return nil, err
	}

	// Get all the private keys
	entKeys, err := usr.QueryKeys().All(context.Background())
	if err != nil {
		zlog.Error().Err(err).Str("id", userid).Send()
		return nil, err
	}

	// Convert the keys to the JKW format
	keys = make([]*jwk.JWK, len(entKeys))

	for i, k := range entKeys {
		jwkKey, err := jwk.NewFromBytes(k.Jwk)
		if err != nil {
			continue
		}
		keys[i] = jwkKey
	}

	// Return an error if no keys were found
	if len(keys) == 0 {
		return nil, fmt.Errorf("the user has no private keys")
	}

	// Convert the keys to public keys
	pubkeys := make([]*jwk.JWK, len(keys))
	for i, k := range keys {
		pubkeys[i] = k.PublicJWKKey()
	}

	return pubkeys, nil
}

func (v *Vault) PrivateKeyByID(id string) (jwkKey *jwk.JWK, err error) {

	// Retrieve key by its ID, which should be unique
	k, err := v.Client.PrivateKey.Get(context.Background(), id)
	if err != nil {
		return nil, err
	}

	// Convert to JWK format
	jwkKey, err = jwk.NewFromBytes(k.Jwk)
	if err != nil {
		return nil, err
	}

	return jwkKey, err
}

// SignWithJWK signs the JWT using the algorithm and key ID in its header
func (v *Vault) SignWithJWK(k *jwk.JWK, claims any) (signedString string, err error) {

	var jsonValue []byte
	var toBeSigned string

	// Create the headerMap
	headerMap := map[string]string{
		"typ": "JWT",
		"alg": k.GetAlg(),
		"kid": k.GetKid(),
	}

	if jsonValue, err = json.Marshal(headerMap); err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString(jsonValue)

	if jsonValue, err = json.Marshal(claims); err != nil {
		return "", err
	}
	fmt.Println("**** Build Claim String ****")
	fmt.Println(string(jsonValue))

	claim := base64.RawURLEncoding.EncodeToString(jsonValue)

	toBeSigned = strings.Join([]string{header, claim}, ".")

	// Perform the signature
	signedString, err = v.SignString(toBeSigned, headerMap["kid"])

	return signedString, err

}

// Sign signs the JWT using the algorithm and key ID in its header
func (v *Vault) Sign(object Signable) (signedString string, err error) {

	var toBeSigned string

	// Convert token to a serialized string to be signed
	toBeSigned, err = object.SigningString()
	if err != nil {
		return "", err
	}

	// Perform the signature
	signedString, err = v.SignString(toBeSigned, object.Kid())

	return signedString, err

}

// SignString signs the string using the key with given ID and using algorithm alg
func (v *Vault) SignString(toBeSigned string, kid string) (signedString string, err error) {

	var signature string

	// Get the private key for signing
	jwkKey, err := v.PrivateKeyByID(kid)
	if err != nil {
		return "", err
	}

	// Convert the key to native
	key, err := jwkKey.GetPrivateKey()
	if err != nil {
		return "", err
	}

	// Get the algorithm from the JWK (it is compulsory for our application)
	alg := jwkKey.GetAlg()

	// Get the method for signing
	method := jwt.GetSigningMethod(alg)

	// Sign the string
	if signature, err = method.Sign(toBeSigned, key); err != nil {
		return "", err
	}

	// Concatenate the signature with a "." as specified in the JWT standards
	return strings.Join([]string{toBeSigned, signature}, "."), nil

}

// VerifySignature verifies that a signature corresponds to a signed string given a key ID and algorithm
func (v *Vault) VerifySignature(signedString string, signature string, alg string, kid string) (err error) {

	// Get the key for verification
	jwkKey, err := v.PrivateKeyByID(kid)
	if err != nil {
		return err
	}

	// Check that the externally specified 'alg' matches the 'alg' in the JWK
	if jwkKey.GetAlg() != alg {
		return fmt.Errorf("alg does not match with alg in the JWK")
	}

	// Convert the key to native
	key, err := jwkKey.GetPublicKey()
	if err != nil {
		return err
	}

	// Get the method to verify
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return fmt.Errorf("signing method (alg) is unavailable")
	}

	// Verify signature
	if err = method.Verify(signedString, signature, key); err != nil {
		return err
	}

	// Verification performed, reply with success
	return nil

}
