package eu.gaiax.difs.aas.config;

import org.keycloak.AuthorizationContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.idm.authorization.Permission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SsiPolicyEnforcer extends PolicyEnforcer {
    
    private static final Logger log = LoggerFactory.getLogger(SsiPolicyEnforcer.class);
    
    public SsiPolicyEnforcer(KeycloakDeployment deployment, AdapterConfig adapterConfig) {
        super(deployment, adapterConfig);
    }
    
    @Override
    public AuthorizationContext enforce(OIDCHttpFacade facade) {
        log.debug("Policy enforcement is enabled. Enforcing policy decisions for path [{}].", facade.getRequest().getURI());

        AuthorizationContext context = new SsiKeycloakPolicyEnforcer(this).authorize(facade);

        log.debug("Policy enforcement result for path [{}] is : {}", facade.getRequest().getURI(), context.isGranted() ? "GRANTED" : "DENIED");
        log.debug("Returning authorization context with permissions:");
        for (Permission permission : context.getPermissions()) {
            log.debug("permission: {}; claims: {}", permission, permission.getClaims());
        }

        return context;
    }
    
}
