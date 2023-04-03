package main

import (
	"fmt"
	"net/http"
	"os"

	configModel "fiware/VCVerifier/config"
	logging "fiware/VCVerifier/logging"
	api "fiware/VCVerifier/openapi"
	ssi "fiware/VCVerifier/ssikit"
	"fiware/VCVerifier/verifier"

	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gookit/config/v2"
	"github.com/gookit/config/v2/yaml"
	"github.com/penglongli/gin-metrics/ginmetrics"
)

// default config file location - can be overwritten by envvar
var configFile string = "server.yaml"

// config objects
var serverConfig configModel.Server
var loggingConfig configModel.Logging
var ssiKitConfig configModel.SSIKit
var verifierConfig configModel.Verifier

/**
* Startup method to run the gin-server.
 */
func main() {

	readConfig()

	logging.Configure(
		loggingConfig.JsonLogging,
		loggingConfig.Level,
		loggingConfig.LogRequests,
		loggingConfig.PathsToSkip)

	logger := logging.Log()

	logger.Infof("Logging config is: %s", logging.PrettyPrintObject(loggingConfig))
	logger.Infof("Server config is: %s", logging.PrettyPrintObject(serverConfig))
	logger.Infof("SSIKit config is: %s", logging.PrettyPrintObject(ssiKitConfig))
	logger.Infof("Verifier config is: %s", logging.PrettyPrintObject(verifierConfig))

	ssiKitClient, err := ssi.NewSSIKitClient(&ssiKitConfig)
	if err != nil {
		logger.Errorf("Was not able to get an ssiKit client. Err: %v", err)
		return
	}
	verifier.InitVerifier(&verifierConfig, ssiKitClient)

	router := getRouter()

	// health check
	router.GET("/health", HealthReq)

	router.Use(cors.New(cors.Config{
		// we need to allow all, since we do not know the potential origin of a wallet
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"POST", "GET"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	//new template engine
	router.HTMLRender = ginview.Default()
	// static files for the frontend
	router.Static("/static", serverConfig.StaticDir)

	// initiate metrics
	metrics := ginmetrics.GetMonitor()
	metrics.SetMetricPath("/metrics")
	metrics.Use(router)

	router.Run(fmt.Sprintf("0.0.0.0:%v", serverConfig.Port))

	logger.Infof("Started router at %v", serverConfig.Port)
}

// initiate the router
func getRouter() *gin.Engine {
	// the openapi generated router uses the defaults, which we want to override to improve and configure logging
	router := gin.New()
	router.Use(logging.GinHandlerFunc(), gin.Recovery())

	for _, route := range api.NewRouter().Routes() {

		switch route.Method {
		case http.MethodGet:
			router.GET(route.Path, route.HandlerFunc)
		case http.MethodPost:
			router.POST(route.Path, route.HandlerFunc)
		case http.MethodPut:
			router.PUT(route.Path, route.HandlerFunc)
		case http.MethodPatch:
			router.PATCH(route.Path, route.HandlerFunc)
		case http.MethodDelete:
			router.DELETE(route.Path, route.HandlerFunc)
		}
	}

	return router
}

// read the config from the config file
func readConfig() {
	config.WithOptions(config.ParseDefault)
	config.AddDriver(yaml.Driver)
	err := config.LoadFiles(configFile)

	if err != nil {
		panic(err)
	}

	serverConfig = configModel.Server{}
	config.BindStruct("server", &serverConfig)

	loggingConfig = configModel.Logging{}
	config.BindStruct("logging", &loggingConfig)

	ssiKitConfig = configModel.SSIKit{}
	config.BindStruct("ssiKit", &ssiKitConfig)

	verifierConfig = configModel.Verifier{}
	config.BindStruct("verifier", &verifierConfig)
}

// allow override of the config-file on init. Everything else happens on main to improve testability
func init() {

	configFileEnv := os.Getenv("CONFIG_FILE")
	if configFileEnv != "" {
		configFile = configFileEnv
	}
	logging.Log().Infof("Will read config from %s", configFile)
}
