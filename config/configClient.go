package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/fiware/VCVerifier/logging"
)

const SERVICES_PATH = "service"

var ErrorCcsNoResponse = errors.New("no_response_from_ccs")
var ErrorCcsErrorResponse = errors.New("error_response_from_ccs")
var ErrorCcsEmptyResponse = errors.New("empty_response_from_ccs")

type HttpClient interface {
	Get(url string) (resp *http.Response, err error)
}

type ConfigClient interface {
	GetServices() (services []ConfiguredService, err error)
}

type HttpConfigClient struct {
	client         HttpClient
	configEndpoint string
}

type ServicesResponse struct {
	Total      int                 `json:"total"`
	PageNumber int                 `json:"pageNumber"`
	PageSize   int                 `json:"pageSize"`
	Services   []ConfiguredService `json:"services"`
}

type ConfiguredService struct {
	Id          string       `json:"id"`
	Credentials []Credential `json:"credentials"`
}

type Credential struct {
	Type                     string   `json:"type"`
	TrustedParticipantsLists []string `json:"trustedParticipantsLists"`
	TrustedIssuersLists      []string `json:"trustedIssuersLists"`
}

func NewCCSHttpClient(configEndpoint string) (client ConfigClient, err error) {

	// no need for a caching client here, since the repo handles the "caching"
	httpClient := &http.Client{}
	return HttpConfigClient{httpClient, getServiceUrl(configEndpoint)}, err
}

func (hcc HttpConfigClient) GetServices() (services []ConfiguredService, err error) {
	var currentPage int = 0
	var pageSize int = 100
	var finished bool = false
	services = []ConfiguredService{}

	for !finished {
		servicesResponse, err := hcc.getServicesPage(currentPage, pageSize)
		if err != nil {
			logging.Log().Warnf("Failed to receive services page %v with size %v. Err: %v", currentPage, pageSize, err)
			return nil, err
		}
		services = append(services, servicesResponse.Services...)
		// we check both, since its possible that druing the iterration new services where added to old pages(total != len(services)).
		// those will be retrieved on next iterration, thus can be ignored
		if len(servicesResponse.Services) < pageSize || servicesResponse.Total == len(services) {
			finished = true
		}
		currentPage++
	}
	return services, err
}

func (hcc HttpConfigClient) getServicesPage(page int, pageSize int) (servicesResponse ServicesResponse, err error) {
	logging.Log().Debugf("Retrieve services from %s for page %v and size %v.", hcc.configEndpoint, page, pageSize)
	resp, err := hcc.client.Get(fmt.Sprintf("%s?pageSize=%v&page=%v", hcc.configEndpoint, pageSize, page))
	if err != nil {
		logging.Log().Warnf("Was not able to get the services from %s. Err: %v", hcc.configEndpoint, err)
		return servicesResponse, err
	}
	if resp == nil {
		logging.Log().Warnf("Was not able to get any response for from %s.", hcc.configEndpoint)
		return servicesResponse, ErrorCcsNoResponse
	}
	if resp.StatusCode != 200 {
		logging.Log().Warnf("Was not able to get the services from %s. Stauts: %v", hcc.configEndpoint, resp.StatusCode)
		return servicesResponse, ErrorCcsErrorResponse
	}
	if resp.Body == nil {
		logging.Log().Info("Received an empty body from the ccs.")
		return servicesResponse, ErrorCcsEmptyResponse
	}

	err = json.NewDecoder(resp.Body).Decode(&servicesResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the ccs-response.")
		return servicesResponse, err
	}

	return servicesResponse, err
}

func getServiceUrl(endpoint string) string {
	if strings.HasSuffix(endpoint, "/") {
		return endpoint + SERVICES_PATH
	} else {
		return endpoint + "/" + SERVICES_PATH
	}
}
