package eu.gaiax.difs.aas.config;

import java.util.Map;

import org.keycloak.adapters.authorization.ClaimInformationPointProviderFactory;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SsiClaimInformationPointProviderFactory implements ClaimInformationPointProviderFactory<SsiClaimInformationPointProvider> {
    
    private static final Logger log = LoggerFactory.getLogger(SsiClaimInformationPointProviderFactory.class);

    @Override
    public String getName() {
        log.debug("getName: returning \"ssi\"");
        return "ssi";
    }

    @Override
    public void init(PolicyEnforcer policyEnforcer) {
        log.debug("init.enter; got enforcer: {}", policyEnforcer);
    }

    @Override
    public SsiClaimInformationPointProvider create(Map<String, Object> config) {
        log.debug("create.enter; got config: {}", config);
        return new SsiClaimInformationPointProvider(config);
    }
}


