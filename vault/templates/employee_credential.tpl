{{define "EmployeeCredential"}}
{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://marketplace.i4trust.fiware.io/2022/credentials/employee/v1"
    ],
    "id": "{{.jti}}",
    "type": ["VerifiableCredential", "EmployeeCredential"],
    "issuer": {
        "id": "{{.issuer.DID}}"
    },
    "issuanceDate": "2022-03-22T14:00:00Z",
    "validFrom": "2022-03-22T14:00:00Z",
    "expirationDate": "2023-03-22T14:00:00Z",
    "credentialSubject": {
        "id": "{{.subject.DID}}",
        "verificationMethod": [
            {{range .VerificationMethod}}
            {
                "id": "{{.subjectDID}}#{{.publicKey.kid}}",
                "type": "JwsVerificationKey2020",
                "controller": "{{.subjectDID}}",
                "publicKeyJwk": {
                    "kid": "{{.publicKey.kid}}",
                    "kty": "{{.publicKey.kty}}",
                    "crv": "{{.publicKey.crv}}",
                    "x": "{{.publicKey.x}}",
                    "y": "{{.publicKey.y}}"
                }
            }
            {{end}}
        ],
        "roles": {{toJson .claims.roles}},
        "name": "{{.claims.name}}",
        "given_name": "{{.claims.given_name}}",
        "family_name": "{{.claims.family_name}}",
        "preferred_username": "{{.claims.preferred_username}}",
        "email": "{{.claims.email}}"
    }
}
{{end}}