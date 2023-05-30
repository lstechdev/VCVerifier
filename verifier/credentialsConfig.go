package verifier

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/patrickmn/go-cache"
	"github.com/procyon-projects/chrono"
)

const CACHE_EXPIRY = 60
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
	initialConfig            *config.ConfigRepo
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
	var scopeCache Cache = cache.New(CACHE_EXPIRY*time.Second, 2*CACHE_EXPIRY*time.Second)
	var trustedParticipantsCache Cache = cache.New(CACHE_EXPIRY*time.Second, 2*CACHE_EXPIRY*time.Second)
	var trustedIssuersCache Cache = cache.New(CACHE_EXPIRY*time.Second, 2*CACHE_EXPIRY*time.Second)

	scb := ServiceBackedCredentialsConfig{configEndpoint: serviceUrl, scopeCache: scopeCache, trustedParticipantsCache: trustedParticipantsCache, trustedIssuersCache: trustedIssuersCache, initialConfig: repoConfig}
	scb.fillStaticValues()
	taskScheduler := chrono.NewDefaultTaskScheduler()
	taskScheduler.ScheduleAtFixedRate(scb.fillCache, time.Duration(30)*time.Second)

	return scb, err
}

func (cc ServiceBackedCredentialsConfig) fillStaticValues() {
	for serviceId, serviceConfig := range cc.initialConfig.Services {
		logging.Log().Debugf("Add to scope cache: %s", serviceId)
		cc.scopeCache.Add(serviceId, serviceConfig.Scope, cache.NoExpiration)
		for vcType, trustedParticipants := range serviceConfig.TrustedParticipants {
			logging.Log().Debugf("Add to trusted participants cache: %s", fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceId, vcType))
			cc.trustedParticipantsCache.Add(fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceId, vcType), trustedParticipants, cache.NoExpiration)

		}
		for vcType, trustedIssuers := range serviceConfig.TrustedIssuers {
			logging.Log().Debugf("Add to trusted issuers cache: %s", fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceId, vcType))
			cc.trustedIssuersCache.Add(fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceId, vcType), trustedIssuers, cache.NoExpiration)
		}
	}
}

func (cc ServiceBackedCredentialsConfig) fillCache(ctx context.Context) {

	// TODO: add fill from service
}

func (cc ServiceBackedCredentialsConfig) GetScope(serviceIdentifier string) (credentialTypes []string, err error) {
	cacheEntry, hit := cc.scopeCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found scope for %s", serviceIdentifier)
		return cacheEntry.([]string), nil
	}
	logging.Log().Debugf("No scope entry for %s", serviceIdentifier)
	return []string{}, nil
}

func (cc ServiceBackedCredentialsConfig) GetTrustedParticipantLists(serviceIdentifier string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	logging.Log().Debugf("Get participants list for %s.", fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceIdentifier, credentialType))
	cacheEntry, hit := cc.trustedParticipantsCache.Get(fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceIdentifier, credentialType))
	if hit {
		logging.Log().Debugf("Found trusted participants %s for %s - %s", cacheEntry.([]string), serviceIdentifier, credentialType)
		return cacheEntry.([]string), nil
	}
	logging.Log().Debugf("No trusted participants for %s - %s", serviceIdentifier, credentialType)
	return []string{}, nil
}

func (cc ServiceBackedCredentialsConfig) GetTrustedIssuersLists(serviceIdentifier string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	logging.Log().Debugf("Get issuers list for %s.", fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceIdentifier, credentialType))
	cacheEntry, hit := cc.trustedIssuersCache.Get(fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceIdentifier, credentialType))
	if hit {
		logging.Log().Debugf("Found trusted issuers for %s - %s", serviceIdentifier, credentialType)
		return cacheEntry.([]string), nil
	}
	logging.Log().Debugf("No trusted issuers for %s - %s", serviceIdentifier, credentialType)
	return []string{}, nil
}
