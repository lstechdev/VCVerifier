package operations

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/fiware/vcbackend/vault"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

var logger = zap.Must(zap.NewDevelopment())

func SSIKitCreateDID(custodianURL string, v *vault.Vault, userid string) (string, error) {
	defer logger.Sync()

	// Create a new DID only if it does not exist
	did, _ := v.GetDIDForUser(userid)
	if len(did) > 0 {
		return did, nil
	}

	// Call the SSI Kit
	agent := fiber.Post(custodianURL + "/did/create")
	bodyRequest := fiber.Map{
		"method": "key",
	}
	agent.JSON(bodyRequest)
	agent.ContentType("application/json")
	agent.Set("accept", "application/json")
	code, returnBody, reqErr := agent.Bytes()
	if len(reqErr) > 0 {
		err := fmt.Errorf("error calling SSI Kit: %v", reqErr[0])
		logger.Error("error calling SSI Kit", zap.Error(err))
		return "", err
	}
	if code != http.StatusOK {
		logger.Error(fmt.Sprintf("Was not able to create the issuer. Status: %d, Message: %s", code, returnBody))
		return "", errors.New("issuer_not_created")
	}

	did = string(returnBody)
	// Store the new DID for the specified user
	v.SetDIDForUser(userid, did)

	return did, nil
}
