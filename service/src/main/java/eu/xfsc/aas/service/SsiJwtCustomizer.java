package eu.xfsc.aas.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
public class SsiJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Autowired
    private  SsiBrokerService ssiBrokerService;

    @Override
    public void customize(JwtEncodingContext context) {
        log.debug("customize.enter; got context with tokenType: {}, grantType: {}, scopes: {}", context.getTokenType().getValue(), 
                context.getAuthorizationGrantType().getValue(), context.getAuthorizedScopes());
        String requestId = getRequestId(context);
        
        boolean updated = false;
        if ("id_token".equals(context.getTokenType().getValue())) {
            OAuth2Authorization auth = context.get(OAuth2Authorization.class);
            OAuth2AuthorizationRequest oar = auth.getAttribute(OAuth2AuthorizationRequest.class.getName());
            Map<String, Object> additionalParams = oar.getAdditionalParameters();
            Map<String, Object> idToken = null;
            Object maxAge = null;
            if (additionalParams != null && !additionalParams.isEmpty()) {
                String sClaims = (String) additionalParams.get("claims");
                Map<String, Object> claims;
                if (sClaims != null) {
                    JacksonJsonParser jsonParser = new JacksonJsonParser();
                    claims = jsonParser.parseMap(sClaims);
                    idToken = (Map<String, Object>) claims.get("id_token");
                    idToken.put(IdTokenClaimNames.SUB, requestId);
                } else {
                    claims = new HashMap<>();
                }
                maxAge = additionalParams.get("max_age");
                if (maxAge != null) {
                    claims.put(IdTokenClaimNames.AUTH_TIME, 1);
                }
                updated = ssiBrokerService.setAdditionalParameters(requestId, claims);
            }
            
            Set<String> claims = idToken == null ? maxAge == null ? Set.of(IdTokenClaimNames.SUB) : Set.of(IdTokenClaimNames.AUTH_TIME, IdTokenClaimNames.SUB) : 
                maxAge == null ? idToken.keySet() : Stream.concat(idToken.keySet().stream(), Set.of(IdTokenClaimNames.AUTH_TIME).stream()).collect(Collectors.toSet()); 
            

            // the below is required in case when additional claims were requested via claims.id_token or max_age params
            Map<String, Object> userDetails = ssiBrokerService.getUserClaims(requestId, false, null, claims); // required?
            if (userDetails != null) {
                for (Map.Entry<String, Object> e: userDetails.entrySet()) {
                    context.getClaims().claim(e.getKey(), e.getValue());
                }
            }
        }
        List<String> claims = new ArrayList<>();
        context.getClaims().claims(c -> claims.addAll(c.keySet()));
        log.debug("customize.exit; updated: {}, claims: {}, for request: {}", updated, claims, requestId);
    }

    private String getRequestId(JwtEncodingContext context) {
        AtomicReference<String> requestId = new AtomicReference<>();
        context.getClaims().claims(claims -> requestId.set((String) claims.get(IdTokenClaimNames.SUB)));
        return requestId.get();
    }

}
