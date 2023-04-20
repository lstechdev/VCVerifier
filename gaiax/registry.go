package gaiax

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fiware/VCVerifier/logging"
)

var ErrorRegistryNoResponse = errors.New("no_response_from_gaiax_registry")

type RegistryClient interface {
	// Get the list of DIDs of the trustable issuers
	GetComplianceIssuers() ([]string, error)
}

type GaiaXRegistryClient struct {
	endpoint string
}

func InitGaiaXRegistryVerifier(url string) RegistryClient{
	return &GaiaXRegistryClient{url}
}

// TODO Could propably cache the response very generously as new issuers are not added often
func (rc *GaiaXRegistryClient) GetComplianceIssuers() ([]string, error) {
	response, err := http.Get(rc.endpoint)

	if err != nil {
		logging.Log().Warnf("Did not receive a valid issuers list response. Err: %v", err)
		return []string{}, err
	}
	if response == nil {
		logging.Log().Warn("Did not receive any response from gaia-x registry.")
		return []string{}, ErrorRegistryNoResponse
	}
	if response.StatusCode != 200 {
		logging.Log().Infof("Did not receive an ok from the registry. Was %s", logging.PrettyPrintObject(response))
		return []string{}, err
	}
	if response.Body == nil {
		logging.Log().Info("Received an empty body for the issuers list.")
		return []string{}, err
	}
	var issuers []string

	err = json.NewDecoder(response.Body).Decode(&issuers)
	if err != nil {
		logging.Log().Warn("Was not able to decode the issuers list.")
		return []string{}, err
	}
	logging.Log().Info("%d issuer dids received.", len(issuers))
	logging.Log().Debugf("Issuers are %v", logging.PrettyPrintObject(issuers))
	return issuers, nil
}
