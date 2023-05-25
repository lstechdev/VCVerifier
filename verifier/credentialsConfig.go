package verifier

import (
	"fmt"
	"net/url"
	"time"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
)

const CACHE_EXPIRY = 30
const CACHE_KEY_TEMPLATE = "%s-%s"

/**
* Provides information about credentialTypes associated with services and there trust anchors.
 */
type CredentialsConfig interface {
	// should return the list of credentialtypes to be requested via the scope parameter
	GetScope(serviceIdentifier string) (credentialTypes []string, err error)
	// get (EBSI TrustedIssuersRegistry compliant) endpoints for the given service/credential combination, to check its issued by a trusted participant.
	GetTrustedParticipantLists(serviceIdentifier string, credentialType string) (trustedIssuersRegistryUrl []string, err error)
	// get (EBSI TrustedIssuersRegistry compliant) endpoints for the given service/credential combination, to check that credentials are issued by trusted issuers
	// and that the issuer has permission to issue such claims.
	GetTrustedIssuersLists(serviceIdentifier string, credentialType string) (trustedIssuersRegistryUrl []string, err error)
}

type ServiceBackedCredentialsConfig struct {
	configEndpoint           *url.URL
	scopeCache               Cache
	trustedParticipantsCache Cache
	trustedIssuersCache      Cache
}

func InitServiceBackedCredentialsConfig(repoConfig *config.ConfigRepo) (credentialsConfig CredentialsConfig, err error) {
	if repoConfig.ConfigEndpoint == "" {
		logging.Log().Warn("No endpoint for the configuration service is configured. Only static configuration will be provided.")
	}
	serviceUrl, err := url.Parse(repoConfig.ConfigEndpoint)
	if err != nil {
		logging.Log().Errorf("The service endpoint %s is not a valid url. Err: %v", repoConfig.ConfigEndpoint, err)
		return
	}
	scopeCache := cache.New(time.Duration(CACHE_EXPIRY)*time.Second, time.Duration(2*CACHE_EXPIRY)*time.Second)
	trustedParticipantsCache := cache.New(time.Duration(CACHE_EXPIRY)*time.Second, time.Duration(2*CACHE_EXPIRY)*time.Second)
	trustedIssuersCache := cache.New(time.Duration(CACHE_EXPIRY)*time.Second, time.Duration(2*CACHE_EXPIRY)*time.Second)
	for serviceId, serviceConfig := range repoConfig.Services {
		scopeCache.Add(serviceId, serviceConfig.Scope, cache.DefaultExpiration)
		for vcType, trustedParticipants := range serviceConfig.TrustedParticipants {
			trustedParticipantsCache.Add(fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceId, vcType), trustedParticipants, cache.DefaultExpiration)
		}
		for vcType, trustedIssuers := range serviceConfig.TrustedIssuers {
			trustedIssuersCache.Add(fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceId, vcType), trustedIssuers, cache.DefaultExpiration)
		}
	}
	return ServiceBackedCredentialsConfig{configEndpoint: serviceUrl, scopeCache: scopeCache, trustedParticipantsCache: trustedParticipantsCache, trustedIssuersCache: trustedIssuersCache}, err
}

func (cc ServiceBackedCredentialsConfig) GetScope(serviceIdentifier string) (credentialTypes []string, err error) {
	cacheEntry, hit := cc.scopeCache.Get(serviceIdentifier)
	if hit {
		return cacheEntry.([]string), nil
	}
	return []string{}, nil
}

func (cc ServiceBackedCredentialsConfig) GetTrustedParticipantLists(serviceIdentifier string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	cacheEntry, hit := cc.trustedParticipantsCache.Get(fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceIdentifier, credentialType))
	if hit {
		return cacheEntry.([]string), nil
	}
	return []string{}, nil
}

func (cc ServiceBackedCredentialsConfig) GetTrustedIssuersLists(serviceIdentifier string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	cacheEntry, hit := cc.trustedIssuersCache.Get(fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceIdentifier, credentialType))
	if hit {
		return cacheEntry.([]string), nil
	}
	return []string{}, nil
}
