/*
 * DID Registry
 *
 * The subset of the [DID Registry as defined by EBSI](https://api-pilot.ebsi.eu/docs/apis/did-registry/v4#/) as currently required by the [VCVerifier](https://github.com/FIWARE/VCVerifier). 
 *
 * API version: v4
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package tir

type ProblemDetails struct {
	// An absolute URI that identifies the problem type. When dereferenced, it SHOULD provide human-readable documentation for the problem type.
	Type_ string `json:"type,omitempty"`
	// A short summary of the problem type.
	Title string `json:"title,omitempty"`
	// The HTTP status code generated by the origin server for this occurrence of the problem.
	Status float64 `json:"status,omitempty"`
	// A human readable explanation specific to this occurrence of the problem.
	Detail string `json:"detail,omitempty"`
	// An absolute URI that identifies the specific occurrence of the problem. It may or may not yield further information if dereferenced.
	Instance string `json:"instance,omitempty"`
}
