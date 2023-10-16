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
	"golang.org/x/exp/maps"
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
	GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error)
	// get (EBSI TrustedIssuersRegistry compliant) endpoints for the given service/credential combination, to check that credentials are issued by trusted issuers
	// and that the issuer has permission to issue such claims.
	GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error)
	RequiredCredentialTypes(serviceIdentifier string, scopes string) (credentialTypes []string, err error)
}

type ServiceBackedCredentialsConfig struct {
	initialConfig *config.ConfigRepo
	configClient  *config.ConfigClient
	serviceCache  Cache
}

func InitServiceBackedCredentialsConfig(repoConfig *config.ConfigRepo) (credentialsConfig CredentialsConfig, err error) {
	var configClient config.ConfigClient
	if repoConfig.ConfigEndpoint == "" {
		logging.Log().Warn("No endpoint for the configuration service is configured. Only static configuration will be provided.")
	} else {

		_, err = url.Parse(repoConfig.ConfigEndpoint)
		if err != nil {
			logging.Log().Errorf("The service endpoint %s is not a valid url. Err: %v", repoConfig.ConfigEndpoint, err)
			return
		}
		configClient, err = config.NewCCSHttpClient(repoConfig.ConfigEndpoint)
		if err != nil {
			logging.Log().Warnf("Was not able to instantiate the config client.")
		}
	}
	var serviceCache Cache = cache.New(CACHE_EXPIRY*time.Second, 2*CACHE_EXPIRY*time.Second)

	scb := ServiceBackedCredentialsConfig{configClient: &configClient, serviceCache: serviceCache, initialConfig: repoConfig}

	scb.fillStaticValues()
	if repoConfig.ConfigEndpoint != "" {
		chrono.NewDefaultTaskScheduler().ScheduleAtFixedRate(scb.fillCache, time.Duration(30)*time.Second)
	}

	return scb, err
}

func (cc ServiceBackedCredentialsConfig) fillStaticValues() {
	for _, configuredService := range cc.initialConfig.Services {
		logging.Log().Debugf("Add to scope cache: %s", configuredService.Id)
		cc.serviceCache.Add(configuredService.Id, configuredService, cache.NoExpiration)
	}
}

func (cc ServiceBackedCredentialsConfig) fillCache(ctx context.Context) {
	client := *(cc.configClient)
	services, err := client.GetServices()
	if err != nil {
		logging.Log().Warnf("Was not able to update the credentials config from the external service. Will try again. Err: %v.", err)
		return
	}
	for _, configuredService := range services {
		cc.serviceCache.Add(configuredService.Id, configuredService, cache.NoExpiration)
	}
}

func (cc ServiceBackedCredentialsConfig) RequiredCredentialTypes(serviceIdentifier string, scope string) (credentialTypes []string, err error) {
	cacheEntry, hit := cc.serviceCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found scope for %s", serviceIdentifier)
		configuredService := cacheEntry.(config.ConfiguredService)
		return configuredService.GetRequiredCredentialTypes(scope), nil
	}
	logging.Log().Debugf("No scope entry for %s", serviceIdentifier)
	return []string{}, nil
}

// FIXME shall we return all scopes or just the default one?
func (cc ServiceBackedCredentialsConfig) GetScope(serviceIdentifier string) (credentialTypes []string, err error) {
	cacheEntry, hit := cc.serviceCache.Get(serviceIdentifier)
	if hit {
		logging.Log().Debugf("Found scope for %s", serviceIdentifier)
		configuredService := cacheEntry.(config.ConfiguredService)
		return maps.Keys(configuredService.ServiceScopes), nil
	}
	logging.Log().Debugf("No scope entry for %s", serviceIdentifier)
	return []string{}, nil
}

func (cc ServiceBackedCredentialsConfig) GetTrustedParticipantLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	logging.Log().Debugf("Get participants list for %s.", fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceIdentifier, credentialType))
	cacheEntry, hit := cc.serviceCache.Get(serviceIdentifier)
	if hit {
		credential, ok := cacheEntry.(config.ConfiguredService).GetCredential(scope, credentialType)
		if ok {
			logging.Log().Debugf("Found trusted participants %s for %s - %s", credential.TrustedParticipantsLists, serviceIdentifier, credentialType)
			return credential.TrustedParticipantsLists, nil
		}
	}
	logging.Log().Debugf("No trusted participants for %s - %s", serviceIdentifier, credentialType)
	return []string{}, nil
}

func (cc ServiceBackedCredentialsConfig) GetTrustedIssuersLists(serviceIdentifier string, scope string, credentialType string) (trustedIssuersRegistryUrl []string, err error) {
	logging.Log().Debugf("Get issuers list for %s.", fmt.Sprintf(CACHE_KEY_TEMPLATE, serviceIdentifier, credentialType))
	cacheEntry, hit := cc.serviceCache.Get(serviceIdentifier)
	if hit {
		credential, ok := cacheEntry.(config.ConfiguredService).GetCredential(scope, credentialType)
		if ok {
			logging.Log().Debugf("Found trusted issuers for %s for %s - %s", credential.TrustedIssuersLists, serviceIdentifier, credentialType)
			return credential.TrustedIssuersLists, nil
		}
	}
	logging.Log().Debugf("No trusted issuers for %s - %s", serviceIdentifier, credentialType)
	return []string{}, nil
}
