## Claims Information Point

The AAS implements the CIP in order to provide an ability to resolve permissions in IAM (keycloak) dynamically.
In the reference implementation keycloak [Policy Enforcers](http://www.keycloak.org/docs/latest/authorization_services/index.html#_enforcer_overview) functionality are used for authorization.

The CIP is found at `GET` `/cip/claims` and takes two query parameters:

- `sub` - the subject or username for which to get the claims
- `scope` - a whitespace seperated list of scopes, i.e. `openid email profile`. Defaults to `openid`.

The endpoint returns a JSON object with the keys being the claim types and the values being the claims.
For example

```json
{
    'sub': 'user123',
    'preferred_username': 'user1',
    'name': 'John',
    'family_name': 'Doe',
    'company': 'John's Company Ltd.',
    'email': 'john@example.org',
}
```

The AAS only forwards user claims it gets from the TSA, so the exact claims that are available depend on the TSA.
