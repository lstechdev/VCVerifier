package operations

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	model "github.com/fiware/vcverifier/model"
	"github.com/fiware/vcverifier/vault"
	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

const verificationPath = "/v1/verify"

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
		err := fmt.Errorf("error calling SSI Kit at: %v", reqErr[0])
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

type verificationRequest struct {
	Policies    []model.Policy               `json:"policies"`
	Credentials []model.VerifiableCredential `json:"credentials"`
}

type verificationResult struct {
	Valid         bool              `json:"valid"`
	PolicyResults map[string]string `json:"policyResults`
}

type verificationResponse struct {
	Valid   bool                 `json:"valid"`
	Results []verificationResult `json:"results"`
}

func VerifyVC(auditorURL string, policies []model.Policy, verifiableCredential model.VerifiableCredential) (result bool, err error) {
	defer logger.Sync()
	auditorAddress := auditorURL + verificationPath
	// Call the SSI Kit
	agent := fiber.Post(auditorURL + verificationPath)
	verificationRequest := verificationRequest{policies, []model.VerifiableCredential{verifiableCredential}}

	agent.JSON(verificationRequest)
	agent.ContentType("application/json")
	agent.Set("accept", "application/json")

	code, returnBody, reqErr := agent.Bytes()
	if len(reqErr) > 0 {
		err := fmt.Errorf("error calling SSI Kit at %s: %v", auditorAddress, reqErr[0])
		logger.Error("error calling SSI Kit", zap.Error(err))
		return false, err
	}
	if code != http.StatusOK {
		err := fmt.Errorf("error calling SSI Kit - status was %d: %s", code, string(returnBody))
		logger.Error(fmt.Sprintf("error calling SSI Kit - response was %d: %s", code, string(returnBody)), zap.Error(err))
		return false, err
	}

	var vr verificationResponse
	json.Unmarshal(returnBody, &vr)

	if vr.Valid {
		return true, err
	} else {
		logger.Info("Verfication failed.")
		logger.Debug(fmt.Sprintf("Detailed result is %v", prettyPrintObject(vr)))
		return false, err
	}
}

func prettyPrintObject(objectInterface interface{}) string {
	jsonBytes, err := json.Marshal(objectInterface)
	if err != nil {
		logger.Debug(fmt.Sprintf("Was not able to pretty print the object: %v", objectInterface))
		return ""
	}
	return string(jsonBytes)
}
