package eu.gaiax.difs.aas.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.authorization.KeycloakAdapterPolicyEnforcer;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.adapters.spi.HttpFacade.Request;
import org.keycloak.authorization.client.ClientAuthorizationContext;
import org.keycloak.common.util.Base64Url;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig.EnforcementMode;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig.MethodConfig;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig.PathConfig;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig.ScopeEnforcementMode;
import org.keycloak.representations.idm.authorization.Permission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SsiKeycloakPolicyEnforcer extends KeycloakAdapterPolicyEnforcer {
    
    private static final Logger log = LoggerFactory.getLogger(SsiKeycloakPolicyEnforcer.class);

    private final PolicyEnforcer policyEnforcer;
    
    public SsiKeycloakPolicyEnforcer(PolicyEnforcer policyEnforcer) {
        super(policyEnforcer);
        this.policyEnforcer = policyEnforcer;
    }
    
    @Override
    public AuthorizationContext authorize(OIDCHttpFacade httpFacade) {
        EnforcementMode enforcementMode = getEnforcerConfig().getEnforcementMode();
        KeycloakSecurityContext securityContext = httpFacade.getSecurityContext();

        if (EnforcementMode.DISABLED.equals(enforcementMode)) {
            if (securityContext == null) {
                httpFacade.getResponse().sendError(401, "Invalid bearer");
            }
            return createEmptyAuthorizationContext(true);
        }

        Request request = httpFacade.getRequest();
        PathConfig pathConfig = getPathConfig(request);

        if (securityContext == null) {
            if (!isDefaultAccessDeniedUri(request)) {
                if (pathConfig != null) {
                    if (EnforcementMode.DISABLED.equals(pathConfig.getEnforcementMode())) {
                        return createEmptyAuthorizationContext(true);
                    } else {
                        challenge(pathConfig, getRequiredScopes(pathConfig, request), httpFacade);
                    }
                } else {
                    handleAccessDenied(httpFacade);
                }
            }
            return createEmptyAuthorizationContext(false);
        }
        
        log.debug("authorize; security context:accessToken {}", decodeToken(securityContext.getTokenString()));
        log.debug("authorize; security context:idToken {}", decodeToken(securityContext.getIdTokenString()));
        
        AccessToken accessToken = securityContext.getToken();

        if (accessToken != null) {
            log.debug("Checking permissions for path [{}] with config [{}].", request.getURI(), pathConfig);

            if (pathConfig == null) {
                if (EnforcementMode.PERMISSIVE.equals(enforcementMode)) {
                    return createAuthorizationContext(accessToken, null);
                }

                if (log.isDebugEnabled()) {
                    log.debug("Could not find a configuration for path [{}%s]", getPath(request));
                }

                if (isDefaultAccessDeniedUri(request)) {
                    return createAuthorizationContext(accessToken, null);
                }

                handleAccessDenied(httpFacade);

                return createEmptyAuthorizationContext(false);
            }

            if (!("/demo/read".equals(pathConfig.getPath()) || "/demo/write".equals(pathConfig.getPath()))) {
              if (EnforcementMode.DISABLED.equals(pathConfig.getEnforcementMode())) {
                  return createAuthorizationContext(accessToken, pathConfig);
              }
            }

            MethodConfig methodConfig = getRequiredScopes(pathConfig, request);
            log.debug("authorize; got method scopes: {}", methodConfig);
            Map<String, List<String>> claims = resolveClaims(pathConfig, httpFacade);
            log.debug("authorize; got claims: {}", claims);

            if (isAuthorized(pathConfig, methodConfig, accessToken, httpFacade, claims)) {
                try {
                    return createAuthorizationContext(accessToken, pathConfig);
                } catch (Exception e) {
                    throw new RuntimeException("Error processing path [" + pathConfig.getPath() + "].", e);
                }
            }

            if (methodConfig != null && ScopeEnforcementMode.DISABLED.equals(methodConfig.getScopesEnforcementMode())) {
                return createEmptyAuthorizationContext(true);
            }

            log.debug("Sending challenge to the client. Path [{}]", pathConfig);

            if (!challenge(pathConfig, methodConfig, httpFacade)) {
                log.debug("Challenge not sent, sending default forbidden response. Path [{}]", pathConfig);
                handleAccessDenied(httpFacade);
            }
        }

        return createEmptyAuthorizationContext(false);
    }
    
    private String decodeToken(String encoded) { 
        if (encoded == null)
            return null;

        String[] parts = encoded.split("\\.");
        if (parts.length < 2 || parts.length > 3) throw new IllegalArgumentException("Parsing error");

        byte[] bytes = Base64Url.decode(parts[1]);
        return new String(bytes);
    }
    
    private AuthorizationContext createEmptyAuthorizationContext(final boolean granted) {
        return new ClientAuthorizationContext(getAuthzClient()) {
            @Override
            public boolean hasPermission(String resourceName, String scopeName) {
                return granted;
            }

            @Override
            public boolean hasResourcePermission(String resourceName) {
                return granted;
            }

            @Override
            public boolean hasScopePermission(String scopeName) {
                return granted;
            }

            @Override
            public List<Permission> getPermissions() {
                return Collections.EMPTY_LIST;
            }

            @Override
            public boolean isGranted() {
                return granted;
            }
        };
    }

    private AuthorizationContext createAuthorizationContext(AccessToken accessToken, PathConfig pathConfig) {
        return new ClientAuthorizationContext(accessToken, pathConfig, getAuthzClient());
    }

    private boolean isDefaultAccessDeniedUri(Request request) {
        String accessDeniedPath = getEnforcerConfig().getOnDenyRedirectTo();
        return accessDeniedPath != null && request.getURI().contains(accessDeniedPath);
    }

    private MethodConfig getRequiredScopes(PathConfig pathConfig, Request request) {
        String method = request.getMethod();

        for (MethodConfig methodConfig : pathConfig.getMethods()) {
            if (methodConfig.getMethod().equals(method)) {
                return methodConfig;
            }
        }

        MethodConfig methodConfig = new MethodConfig();

        methodConfig.setMethod(request.getMethod());
        List scopes = new ArrayList<>();

        if (Boolean.TRUE.equals(getEnforcerConfig().getHttpMethodAsScope())) {
            scopes.add(request.getMethod());
        } else {
            scopes.addAll(pathConfig.getScopes());
        }

        methodConfig.setScopes(scopes);
        methodConfig.setScopesEnforcementMode(PolicyEnforcerConfig.ScopeEnforcementMode.ANY);

        return methodConfig;
    }

    private PathConfig getPathConfig(Request request) {
        return isDefaultAccessDeniedUri(request) ? null : policyEnforcer.getPathMatcher().matches(getPath(request));
    }

    private String getPath(Request request) {
        return request.getRelativePath();
    }


}
