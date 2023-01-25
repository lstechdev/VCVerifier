{{define "PacketDeliveryCredential"}}
{{ $now := now | unixEpoch }}

sub: "{{.subjectDID}}"
jti: "{{.jti}}"
iss: "{{.issuerDID}}"
nbf: "{{ $now }}"
iat: "{{ $now }}"
exp: "{{ add $now 10000 }}"
nonce: "{{ randBytes 12 }}"
vc:
    @context:
        - "https://www.w3.org/2018/credentials/v1"
        - "https://pd.i4trust.fiware.io/2022/credentials/employee/v1"
    id: "{{.jti}}"
    type: ["VerifiableCredential", "{{.credName}}"]
    issuer: "{{.issuerDID}}"
    issuanceDate: "{{ $now }}"

    credentialSubject:
        id: "{{.subjectDID}}"
        given_name: "{{.claims.given_name}}"
        family_name: "{{.claims.family_name}}"
        email: "{{.claims.email}}"
        roles:
            {{- range .claims.roles}}
            - target:  {{.target}}
              names:
                {{- range .names}}
                - {{.}}
                {{- end}}
            {{- end}}
        {{with .verificationMethod}}
        verificationMethod:
            {{range .verificationMethod}}
            - id: "{{.subjectDID}}#{{.publicKey.kid}}"
            type: "JwsVerificationKey2020"
            controller: "{{.subjectDID}}"
            publicKeyJwk:
                kid: "{{.publicKey.kid}}"
                kty: "{{.publicKey.kty}}"
                crv: "{{.publicKey.crv}}"
                x: "{{.publicKey.x}}"
                y: "{{.publicKey.y}}"
            {{end}}
        {{end}}
{{end}}