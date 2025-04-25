## AAS Installation & Configuration

Deployment scripts were provided to deploy services in a Kubernetes environment, see `/service/deploy` folder. The AAS Server installation can be started with Service:

```shell
>kubectl apply -f service.yaml
```
Then install secrets:

```shell
>kubectl apply -f secret-keys.yaml
>kubectl apply -f secret-oidc.yaml
>kubectl apply -f secret-siop.yaml
```
You can change secret values to what is required, just make sure the same values are used in Keycloak deployment for OIDC and SIOP identity providers. Also note 
Keycloak will generate new values for all secrets after realm import procedure, so it'll be required to set proper values in IdP secrets and generate new Initial 
Access Token for Client Registration and copy its value to `secret-keys.yaml` `stringData.iat` value.

AAS and keycloak hosts must be set in environment variables specified in `deployment.yaml`. A wildcard certificate was provided in `wildcard-gxfs-dev-secret.yaml` file for domain `*.gxfs.dev` and used in Ingress settings. If you use other domain name please set it properly in `deployment.yaml` file, default settings are:

            - name: AAS_IAM_BASE_URI
              value: https://key-server.gxfs.dev
            - name: AAS_OIDC_ISSUER
              value: https://auth-server.gxfs.dev

Then install the AAS Deployment and Ingress:

```
>kubectl apply -f deployment.yaml
>kubectl apply -f ingress.yaml
```

### Configuration

All service settings are specified in the base `application.yml` file and its profile-specific extensions:
- `application-test.yml`: for basic test environment
- `application-test-suite.yml`: for testing with Conformance Suite in test environment
- `application-prod.yml`: for production environment

You can specify which profile should be active by setting the `SPRING_PROFILES_ACTIVE` environment variable to the profile name (in this case either `test`, `test-suite` or `prod`).
You can find these profile config files in the `/service/src/main/resources` directory in this repository.

Profile-specific settings override what is specified in the base `application.yml` (default) profile. If some value not set in profile-specific file then 
default value used.
The full list of AAS properties is:

| Property                             | Description                                      | Default value                                                 |
|--------------------------------------|:-------------------------------------------------|:--------------------------------------------------------------|
| aas.cache.size                       | Maximum cache Size of the local caches for Authentications and Claims  | 0 (no restriction by size)              |
| aas.cache.ttl                        | Time-to-Live for cached Authentications and Claims | 5m (5 minutes)                                              |
|                                      |                                                  |                                                               |
| aas.iam.base-uri                     | IAM base URI                                     | http://key-server:8080                                        |
| aas.iam.iat.dcr-uri                  | IAM Client Registration endpoint                 | /realms/gaia-x/clients-registrations/openid-connect           |
| aas.iam.iat.secret                   | Client Registration IAT value (overwritten in secret-keys iat value)   | "{noop}iat"                             | 
| aas.iam.clients.oidc.id              | OIDC Broker Client identifier                    | aas-app-oidc                                                  |
| aas.iam.clients.oidc.secret          | OIDC Broker Client secret                        | "{noop}secret"                                                |
| aas.iam.clients.oidc.redirect-uri    | OIDC Broker Client redirect URI                  | ${aas.iam.base-uri}/realms/gaia-x/broker/ssi-oidc/endpoint    |
| aas.iam.clients.siop.id              | SIOP Broker Client identifier                    | aas-app-siop                                                  |
| aas.iam.clients.siop.secret          | SIOP Broker Client secret                        | "{noop}secret2"                                               |
| aas.iam.clients.siop.redirect-uri    | SIOP Broker Client redirect URI                  | ${aas.iam.base-uri}/realms/gaia-x/broker/ssi-siop/endpoint    |
|                                      |                                                  |                                                               |
| aas.jwk.length                       | JWKS key pair generator key length               | 3072                                                          |
| aas.jwk.secret                       | JWKS private key secret                          | 96ec048e-c640-4cfd-bc82-6571810a9d0f                          |
|                                      |                                                  |                                                               |
| aas.oidc.issuer                      | OIDC issuer value                                | http://auth-server:9000                                       |
| aas.siop.issuer                      | SIOP request static issuer value                 | https://self-issued.me/v2                                     |
| aas.siop.clock-skew                  | SIOP request clock skew value                    | 5s                                                            |
| aas.scopes                           | Supported OIDC scopes with their claims          | _openid_: sub, iss, auth_time <br>_profile_: name, given_name, family_name, middle_name, preferred_username, gender, birthdate, updated_at <br>_email_: email, email_verified                                                         |
|                                      |                                                  |                                                               |
| aas.token.ttl                        | Time-to-Live for issued ID tokens                | 5m                                                            |
|                                      |                                                  |                                                               |
| aas.tsa.url                          | TSA base URL (used in prod profile only)         | http://trustservice/api                                       |
| aas.tsa.repo                         | TSA policy evaluation request repo value         | aisbl                                                         |
| aas.tsa.group                        | TSA policy evaluation request group value        | aisbl                                                         |
| aas.tsa.version                      | TSA policy evaluation request API version value  | 1.0                                                           |
| aas.tsa.action                       | TSA policy evaluation request action value       | evaluate                                                      |
| aas.tsa.delay                        | Number of milliseconds to wait between requests to TSA policy evaluation API                      | 500          |
| aas.tsa.duration                     | Total number of milliseconds to wait for non-pending response from TSA policy evaluation API      | 5000         |
| aas.tsa.request.count                | Number of requests to perform to TSA policy evaluation API (used in test profiles only)           | 2            |
| aas.tsa.statuses.GetLoginProofResult | Status to return in response from TSA policy evaluation API for GetLoginProofResult policy (used in test profiles only)   | ACCEPTED                                                      |
| aas.tsa.statuses.GetIatProofResult   | Status to return in response from TSA policy evaluation API for GetIatProofResult policy (used in test profiles only)     | ACCEPTED                                                      |


### Configuring the metadata database

The AAS uses an SQL database (in the reference setup, this is a PostgrSQL database). The settings to configure are 

- `spring.datasource.url` - The URL where the database is reachable, something like: `jdbc:postgresql://postgresql-aas:5432/aas`
- `spring.datasource.username` - The username to access the database
- `spring.datasource.password` - The password to access the database

### Updating configuration settings with environment variables

Any AAS property can be overwritten with environment variable in uppercase form: `aas.iam.base-uri -> AAS_IAM_BASE_URI`, where all separators 
(dots, hyphens) are substituted with underscores.

Any other Spring Boot setting can be also set via profile property and overwritten with environment variable. Profile to be used is specified in `deployment.yaml`
with environment variable as follows:

            - name: SPRING_PROFILES_ACTIVE
              value: test

`DEBUG` logging levels are enabled for some loggers in default/test profiles, and only `INFO` logging level is enabled in prod profile.

The Service can be managed and monitored via [Spring Actuator endpoints](https://docs.spring.io/spring-boot/docs/current/actuator-api/htmlsingle/). All [Actuator 
endpoints](http://78.138.66.89:9000/actuator) are accessible with default/test profiles, but only some of them (`/health`, `/info`, `/metrics`, `/prometheus`) are enabled in prod profile.