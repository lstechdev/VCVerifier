{{define "employeecopy"}}
{
    "iss": "{{.IssuerDID}}",
    "sub": "{{.SubjectDID}}",
    "exp": "2023-03-22T14:00:00Z",
    "nbf": "2022-03-22T14:00:00Z",
    "jti": "https://pdc.i4trust.fiware.io/credentials/1872",
    "vc": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://marketplace.i4trust.fiware.io/2022/credentials/employee/v1"
        ],
        "id": "https://pdc.i4trust.fiware.io/credentials/1872",
        "type": ["VerifiableCredential", "EmployeeCredential"],
        "issuer": {
            "id": "did:elsi:EU.EORI.NLPACKETDEL"
        },
        "issuanceDate": "2022-03-22T14:00:00Z",
        "validFrom": "2022-03-22T14:00:00Z",
        "expirationDate": "2023-03-22T14:00:00Z",
        "credentialSubject": {
            "id": "{{.SubjectDID}}",
            "verificationMethod": [
                {
                    "id": "{{.SubjectDID}}#key1",
                    "type": "JwsVerificationKey2020",
                    "controller": "{{.SubjectDID}}",
                    "publicKeyJwk": {
                    "kid": "key1",
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "lJtvoA5_XptBvcfcrvtGCvXd9bLymmfBSSdNJf5mogo",
                    "y": "fSc4gZX2R3QKKfHvS3m2vGSVSN8Xc04qsquyfEM55Z0"
                    }
                }
            ],
            "roles": [
                {
                    "target": "did:elsi:EU.EORI.NLMARKETPLA",
                    "names": ["seller", "buyer"]
                }
            ],
            "name": "{{.Name}}",
            "given_name": "{{.Given_name}}",
            "family_name": "{{.Family_name}}",
            "preferred_username": "{{.Preferred_username}}",
            "email": "{{.Email}}"
        }
    }
}
{{end}}