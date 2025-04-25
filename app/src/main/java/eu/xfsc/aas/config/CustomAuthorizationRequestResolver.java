package eu.xfsc.aas.config;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;


public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    
    private final static Logger log = LoggerFactory.getLogger(CustomAuthorizationRequestResolver.class);

    private OAuth2AuthorizationRequestResolver defaultResolver;
    private String registrationId;
    private Set<String> scopes = Set.of("openid");

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository repo, String authorizationRequestBaseUri) {
        defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(repo, authorizationRequestBaseUri);
        registrationId = authorizationRequestBaseUri.substring(authorizationRequestBaseUri.lastIndexOf('/') + 1);
    }
    
    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        log.debug("resolve1.enter; request: {}", request);
        OAuth2AuthorizationRequest req = defaultResolver.resolve(request);
        if (req == null && request.getServletPath().endsWith("/" + registrationId) && request.getParameter("session_state") == null) {
            CustomHttpRequest copy = new CustomHttpRequest(request);
            copy.addParameter("action", "login");
            req = defaultResolver.resolve(copy, registrationId);
        } 
        if (req != null) {
            req = customizeAuthorizationRequest(req);
            log.debug("resolve1; scopes: {}", this.scopes);
        }
        log.debug("resolve1.exit; returning: {}", req);
        return req;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        log.debug("resolve2.enter; request: {}, regId: {}", request, clientRegistrationId);
        OAuth2AuthorizationRequest req = defaultResolver.resolve(request, clientRegistrationId);
        if (req != null) {
            req = customizeAuthorizationRequest(req);
            log.debug("resolve2; scopes: {}", this.scopes);
        }
        log.debug("resolve2.exit; returning: {}", req);
        return req;
    }
    
    public void setScopes(Collection<String> scopes) {
        this.scopes = new HashSet<>(scopes);
        log.debug("setScopes; scopes: {}", this.scopes);
    }

    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest req) {
        return OAuth2AuthorizationRequest.from(req).scopes(scopes).build();
    }


    private class CustomHttpRequest extends HttpServletRequestWrapper {

        private HashMap<String, String> params = new HashMap<>();

        public CustomHttpRequest(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getParameter(String name) {
            if (params.get(name) != null ) {
                return params.get(name);
            }
            return super.getParameter(name);
        }

        void addParameter(String name, String value) {
            params.put( name, value );
        }
    }

}
