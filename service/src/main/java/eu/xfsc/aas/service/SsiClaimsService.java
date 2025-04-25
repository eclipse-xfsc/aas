package eu.xfsc.aas.service;

import static eu.xfsc.aas.model.SsiAuthErrorCodes.*;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.SERVER_ERROR;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import eu.xfsc.aas.cache.DataCache;
import eu.xfsc.aas.cache.caffeine.CaffeineDataCache;
import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.generated.model.AccessRequestStatusDto;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public abstract class SsiClaimsService {
    
    @Value("${aas.cache.size}")
    private int cacheSize;
    @Value("${aas.cache.ttl}")
    private Duration ttl;
    @Value("${aas.tsa.delay}")
    private long delay;
    @Value("${aas.tsa.duration}")
    private long duration;
    
    protected final TrustServiceClient trustServiceClient;
    
    protected DataCache<String, Map<String, Object>> claimsCache;
    
    public SsiClaimsService(TrustServiceClient trustServiceClient) {
        this.trustServiceClient = trustServiceClient;
    }
    
    @PostConstruct
    public void init() {
    	log.info("init; cacheSize: {}, ttl: {}", cacheSize, ttl);
        claimsCache = new CaffeineDataCache<>(1024, ttl, null); 
    }
    
    protected long getTimeout() {
    	return duration;
    }
    
    protected Map<String, Object> getTrustedClaims(String policy, String requestId, Map<String, Object> restrictions) {
        Map<String, Object> evaluation = trustServiceClient.evaluate(policy, initEvaluationParams(requestId, restrictions));

        Object o = evaluation.get(TrustServiceClient.PN_STATUS);
        if (o == null || !(o instanceof AccessRequestStatusDto)) {
            //log.error("loadTrustedClaims; unknown response status: {}", o);
            throw new OAuth2AuthenticationException(SERVER_ERROR);
        }
        return evaluation;
    }

    protected Map<String, Object> loadTrustedClaims(String policy, String requestId, Map<String, Object> restrictions) {
        Instant finish = Instant.now().plusMillis(duration);
        while (Instant.now().isBefore(finish)) {
            Map<String, Object> evaluation = trustServiceClient.evaluate(policy, initEvaluationParams(requestId, restrictions));

            Object o = evaluation.get(TrustServiceClient.PN_STATUS);
            if (o == null || !(o instanceof AccessRequestStatusDto)) {
                //log.error("loadTrustedClaims; unknown response status: {}", o);
                throw new OAuth2AuthenticationException(SERVER_ERROR);
            }

            switch ((AccessRequestStatusDto) o) {
                case ACCEPTED:
                    return evaluation;
                case PENDING:
                	delayNextRequest();
                	break;
                case REJECTED:
                    throw new OAuth2AuthenticationException(LOGIN_REJECTED);
                case TIMED_OUT:
                    throw new OAuth2AuthenticationException(LOGIN_TIMED_OUT);
            }
        }
        throw new OAuth2AuthenticationException(LOGIN_TIMED_OUT);
    }
    
    private Map<String, Object> initEvaluationParams(String requestId, Map<String, Object> restrictions) {
    	if (restrictions == null) {
    		return Map.of(TrustServiceClient.PN_REQUEST_ID, requestId);
    	}
    	return Map.of(TrustServiceClient.PN_REQUEST_ID, requestId, "restrictions", restrictions);
    }
    
    private void delayNextRequest() {
        try {
            TimeUnit.MILLISECONDS.sleep(delay);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
    

}
