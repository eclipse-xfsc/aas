package eu.xfsc.aas.service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

import eu.xfsc.aas.cache.DataCache;
import eu.xfsc.aas.cache.caffeine.CaffeineDataCache;


public class SsiAuthorizationService implements OAuth2AuthorizationService {
    
    private static final Logger log = LoggerFactory.getLogger(SsiAuthorizationService.class);
    
    private final DataCache<String, OAuth2Authorization> authorizations;
    private final Map<String, String> codes;

    public SsiAuthorizationService(int cacheSize, Duration ttl) {
        this.authorizations = new CaffeineDataCache<>(cacheSize, ttl, this::synchronize);
        this.codes = new ConcurrentHashMap<>();
    }
    
    public void synchronize(String key, OAuth2Authorization value, boolean replaced) {
        boolean removed = false;
        log.debug("synchronize; got key: {}, authorization: {}, replaced: {}", key, printAuth(value), replaced);
        if (replaced) {
            //
        } else {
            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = value.getToken(OAuth2AuthorizationCode.class);
            if (authorizationCode != null) {
                removed = codes.remove(authorizationCode.getToken().getTokenValue()) != null;
            }
        }
        log.debug("synchronize.exit; removed: {}, authorizations: {}, codes: {}", removed, authorizations.estimatedSize(), codes.size());
    }
    
    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        log.debug("save.enter; got authorization: {}", printAuth(authorization));
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            codes.put(authorizationCode.getToken().getTokenValue(), authorization.getId());
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        if (refreshToken != null) {
            codes.put(refreshToken.getToken().getTokenValue(), authorization.getId());
        }
        
        this.authorizations.put(authorization.getId(), authorization);
        log.debug("save.exit; authorizations: {}, codes: {}", authorizations.estimatedSize(), codes.size());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        log.debug("remove.enter; got authorization: {}", printAuth(authorization));
        this.authorizations.remove(authorization.getId());
        log.debug("remove.exit; authorizations: {}, codes: {}", authorizations.estimatedSize(), codes.size());
    }

    @Nullable
    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.authorizations.get(id);
    }

    @Nullable
    @Override
    public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        String tkType = tokenType == null ? null : tokenType.getValue();
        log.debug("findByToken.enter; got token: {}, type: {}", token, tkType);
        //if ("code".equals(tokenType.getValue())) {
            String id = codes.get(token);
            if (id != null) {
                OAuth2Authorization authorization = findById(id);
                log.debug("findByToken.exit; returning auth from codes: {}", printAuth(authorization));
                return authorization;
            }
        //}
        
        log.info("findByToken.exit; no authorization found for token: {}, type: {}; authorizations size: {}, codes size: {}", 
                token, tkType, authorizations.estimatedSize(), codes.size());
        //if (token.startsWith("${")) {
        //    try {
        //        throw new Exception("debug");
        //    } catch (Exception ex) {
        //    	log.error("findByToken;", ex);
        //    }
        //}
        return null;
    }

    private String printAuth(OAuth2Authorization authorization) {
        return "[id: " + authorization.getId() + ", principalName: " + authorization.getPrincipalName() +
            ", registeredClientId: " + authorization.getRegisteredClientId() + ", accessToken: " + (authorization.getAccessToken() == null ? 
                    null : authorization.getAccessToken().getToken().getTokenType().getValue() + ":" + authorization.getAccessToken().getToken().getTokenValue()) +
            ", attributes: " + authorization.getAttributes() + ", authorizationGrantType: " + (authorization.getAuthorizationGrantType() == null ? 
                    null : authorization.getAuthorizationGrantType().getValue()) +
            ", refreshToken: " + authorization.getRefreshToken() + "]";
    }

}
