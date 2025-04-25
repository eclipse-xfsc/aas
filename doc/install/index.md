## Installation & Configuration Guide

- [AAS Installation](./aas)
- [Keycloak setup](./keycloak)
- [Cryptographic Initialization](./crypto)

As a result of Login operation AAS returns user claims. The claims corresponds to scopes requested in the initial `authorize` request. Currently AAS supports a subset of [standard scopes and claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) specified in [the OIDC specification](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims):

openid: *sub, iss, auth_time*<br>
profile: *name, given_name, family_name, middle_name, preferred_username, gender, birtdate, updated_at*<br>
email: *email, email_verified*<br>

It is expected that the set of supported scopes and their claims will be extended in the future. Supported scopes and claims can be configured in AAS settings, see the [AAS Installation](./aas) section
