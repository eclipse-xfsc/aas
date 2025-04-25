package eu.xfsc.aas.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class SsiUserInfoAuthProvider implements AuthenticationProvider {

    private static final Logger log = LoggerFactory.getLogger(SsiUserInfoAuthProvider.class);
    
    private SsiBrokerService ssiBroker;
    
    public SsiUserInfoAuthProvider(SsiBrokerService ssiBroker) {
    	this.ssiBroker = ssiBroker;
    }
    
    @SuppressWarnings("unchecked")
	@Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.debug("authenticate.enter; got authentication: {}", authentication);
        String requestId = null;
        List<String> scopes = null;
        if (authentication instanceof OidcUserInfoAuthenticationToken) {
            requestId = ((JwtAuthenticationToken) authentication.getPrincipal()).getToken().getSubject();
            scopes = ((JwtAuthenticationToken) authentication.getPrincipal()).getToken().getClaimAsStringList("scope");
        }
        log.debug("authenticate; subject: {}, scopes: {}", requestId, scopes);
        
        boolean needAuthTime = false;
        Set<String> additionalClaims;
        Map<String, Object> additionalParams = ssiBroker.getAdditionalParameters(requestId);
        if (additionalParams != null) {
            additionalClaims = new HashSet<>();
            Map<String, Object> userInfo = (Map<String, Object>) additionalParams.get("userinfo");
            if (userInfo != null) {
                additionalClaims.addAll(userInfo.keySet());
            }
            if (additionalParams.get(IdTokenClaimNames.AUTH_TIME) != null || additionalParams.get("max_age") != null) {
                additionalClaims.add(IdTokenClaimNames.AUTH_TIME);
                needAuthTime = true;
            }
        } else {
            additionalClaims = Collections.emptySet();
        }

        OidcUserInfo.Builder uiBuilder = OidcUserInfo.builder();
        Map<String, Object> userDetails = ssiBroker.getUserClaims(requestId, false, scopes, additionalClaims); //required?
        //log.debug("authenticate; user claims: {}", userDetails);
        if (userDetails != null) {
            for (Map.Entry<String, Object> e: userDetails.entrySet()) {
                if (!IdTokenClaimNames.AUTH_TIME.equals(e.getKey()) || needAuthTime) {
                    uiBuilder.claim(e.getKey(), e.getValue());
                }
            }
        }
        List<String> claims = new ArrayList<>();
        uiBuilder.claims(c -> claims.addAll(c.keySet()));
        OidcUserInfoAuthenticationToken token = new OidcUserInfoAuthenticationToken(authentication, uiBuilder.build());
        log.debug("authenticate.exit; returning claims: {}, for subject: {}", claims, requestId);
        return token;
    }

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcUserInfoAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
