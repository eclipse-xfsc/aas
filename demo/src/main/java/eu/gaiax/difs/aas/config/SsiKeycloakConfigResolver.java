package eu.gaiax.difs.aas.config;

import java.util.concurrent.Callable;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

public class SsiKeycloakConfigResolver extends KeycloakSpringBootConfigResolver {
    
    private static final Logger log = LoggerFactory.getLogger(SsiKeycloakConfigResolver.class);
    
    @Autowired(required=false)
    private AdapterConfig adapterConfig;
    
    private KeycloakDeployment stored;
    
    @Override
    public KeycloakDeployment resolve(OIDCHttpFacade.Request request) {
        log.trace("resolve.enter; got request: {}", request);
        KeycloakDeployment deployment = super.resolve(request);
        if (stored != deployment) {
            //setup deployment
            deployment.setPolicyEnforcer(new Callable<PolicyEnforcer>() {
                PolicyEnforcer policyEnforcer;
                @Override
                public PolicyEnforcer call() {
                    if (policyEnforcer == null) {
                        synchronized (deployment) {
                            if (policyEnforcer == null) {
                                policyEnforcer = new SsiPolicyEnforcer(deployment, adapterConfig);
                            }
                        }
                    }
                    return policyEnforcer;
                }
            });            
            stored = deployment;
        }
        log.trace("resolve.exit; returning: {}", deployment);
        return deployment;
    }

}
