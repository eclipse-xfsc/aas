package eu.gaiax.difs.aas.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.adapters.authorization.ClaimInformationPointProvider;
import org.keycloak.adapters.spi.HttpFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SsiClaimInformationPointProvider implements ClaimInformationPointProvider {

    private static final Logger log = LoggerFactory.getLogger(SsiClaimInformationPointProvider.class);
    
    private final Map<String, Object> config;

    public SsiClaimInformationPointProvider(Map<String, Object> config) {
        this.config = config;
        log.debug("<init>; config: {}", config);
    }

    @Override
    public Map<String, List<String>> resolve(HttpFacade httpFacade) {
        log.debug("resolve.enter; facade: {}", httpFacade);
        Map<String, List<String>> claims = new HashMap<>();
        // put whatever claim you want into the map
        return claims;
    }
}