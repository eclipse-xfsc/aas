package eu.xfsc.aas.controller;

import java.util.Arrays;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.service.SsiBrokerService;
import eu.xfsc.aas.service.SsiIatService;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/cip")
public class CipController {

    private final SsiIatService ssiIatService;
    private final SsiBrokerService ssiBrokerService;

    // this method can be used for asynch ssi authentication too..  

    @ResponseBody
    @GetMapping(value = "/claims", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> getClaims(@RequestParam Map<String, Object> params) { 
        String subject = (String) params.get(IdTokenClaimNames.SUB);
        String scope = (String) params.get(OAuth2ParameterNames.SCOPE);
        if (scope == null) {
            scope = "openid";
        }
        String namespace = (String) params.get(TrustServiceClient.PN_NAMESPACE);
        if (TrustServiceClient.NS_ACCESS.equals(namespace)) {
            return ssiIatService.getIatProofClaims(subject, scope, params);
        }
        return ssiBrokerService.loadSubjectClaims(subject, Arrays.asList(scope.split(" ")));
    }
    
}
