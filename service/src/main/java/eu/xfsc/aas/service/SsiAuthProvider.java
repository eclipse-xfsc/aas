package eu.xfsc.aas.service;

import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.SERVER_ERROR;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import eu.xfsc.aas.model.SsiClientCustomClaims;

public class SsiAuthProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(SsiAuthProvider.class);

    @Autowired
    private SsiBrokerService ssiBrokerService;
    @Autowired
    private SsiClientsRepository ssiClientsRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authenticate.enter; got authentication: {}; {}", authentication, authentication.getCredentials());

        String requestId = (String) authentication.getPrincipal();
        String clientId = (String) authentication.getCredentials();
        RegisteredClient client = ssiClientsRepository.findByClientId(clientId);
        if (client == null) {
            log.warn("authenticate.error; no client found for {}:{}", clientId, requestId);
            throw new OAuth2AuthenticationException(SERVER_ERROR);
        }
        
        String authType = client.getClientSettings().getSetting(SsiClientCustomClaims.SSI_AUTH_TYPE);
        boolean required = SsiClientCustomClaims.AUTH_TYPE_OIDC.equalsIgnoreCase(authType);
        Map<String, Object> claims = ssiBrokerService.getUserClaims(requestId, required);
        if (claims == null) {
            // wrong principal/requestId?
            log.warn("authenticate.error; no claims found for {}:{}", authType, requestId);
            throw new OAuth2AuthenticationException(SERVER_ERROR);
        }
        
        if (SsiClientCustomClaims.AUTH_TYPE_SIOP.equalsIgnoreCase(authType)) {
            String error = (String) claims.get("error");
            if (error != null) {
                OAuth2Error err;
                String[] parts = error.split(":");
                if (parts.length > 1) {
                    err = new OAuth2Error(parts[0].trim(), parts[1].trim(), null);
                } else {
                    err = new OAuth2Error(parts[0]);
                }
                log.warn("authenticate.error; got SIOP callback error: {}", error);
                throw new OAuth2AuthenticationException(err);
            }
        }
        
        Set<String> scopes = ssiBrokerService.getUserScopes(requestId);
        List<GrantedAuthority> authorities = scopes.stream().map(s -> new SimpleGrantedAuthority("SCOPE_" + s)).collect(Collectors.toList()); 
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), 
                authentication.getCredentials(), authorities);
        token.setDetails(authentication.getDetails());

        log.debug("authenticate.exit; returning: {}", token);
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        boolean result = authentication.equals(UsernamePasswordAuthenticationToken.class); 
        log.debug("supports.exit; got authentication: {}, returning: {}", authentication, result);
        return result;
    }
}
