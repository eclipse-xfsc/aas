## OIDC Configuration

AAS provides a standard [OIDC Discovery Endpoint](https://openid.net/specs/openid-connect-discovery-1_0.html) at /.well-known/openid-configuration. The information exposed at this endpoint is: 

    {
      "issuer": "{base-server-url}", 
      "authorization_endpoint": "{base-server-url}/oauth2/authorize", 
      "userinfo_endpoint": "{base-server-url}/userinfo", 
      "jwks_uri": "{base-server-url}/oauth2/jwks", 
      "scopes_supported": ["openid", "profile", "email"], 
      "response_types_supported": ["code"], 
      "grant_types_supported": ["authorization_code"], 
      "token_endpoint":"{base-server-url}/oauth2/token",
      "token_endpoint_auth_methods_supported": ["client_secret_basic"], 
      "subject_types_supported": ["public"], 
      "id_token_signing_alg_values_supported": ["RS256"], 
      "userinfo_signing_alg_values_supported": ["RS256"], 
      "display_values_supported": ["page"], 
      "claims_supported": ["iss", "sub", "auth_time", "name", "given_name", "family_name", "middle_nickname", "preferred_username", "gender", "birthdate", "updated_at", "email", "email_verified"], 
      "claims_locales_supported": ["en"],
      "ui_locales_supported": ["en", "de", "fr"]
    }

