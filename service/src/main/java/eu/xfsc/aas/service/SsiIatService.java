package eu.xfsc.aas.service;

import eu.xfsc.aas.client.IamClient;
import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.generated.model.AccessRequestDto;
import eu.xfsc.aas.generated.model.AccessRequestStatusDto;
import eu.xfsc.aas.generated.model.AccessResponseDto;
import eu.xfsc.aas.generated.model.ServiceAccessScopeDto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import static eu.xfsc.aas.model.TrustServicePolicy.GET_IAT_PROOF_INVITATION;
import static eu.xfsc.aas.model.TrustServicePolicy.GET_IAT_PROOF_RESULT;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class SsiIatService extends SsiClaimsService {

    private static final Logger log = LoggerFactory.getLogger(SsiIatService.class);
    private static final String PN_TOKEN = "registration_access_token";

    @Value("${aas.iam.iat.redirect-uri}")
    private String redirectUri;
    private final IamClient iamClient;

    public SsiIatService(TrustServiceClient trustServiceClient, IamClient iamClient) {
        super(trustServiceClient);
        this.iamClient = iamClient;
    }

    public AccessResponseDto evaluateIatProofInvitation(AccessRequestDto accessRequestDto) {
        log.debug("evaluateIatProofInvitation.enter; got request: {}", accessRequestDto);
        Map<String, Object> evalRequest = iatRequestToMap(accessRequestDto);
        Map<String, Object> evalResponse = evaluateIatProofInvitation(evalRequest);
        AccessResponseDto accessResponseDto = new AccessResponseDto().subject(accessRequestDto.getSubject())
                .entity(accessRequestDto.getEntity()) 
                .status((AccessRequestStatusDto) evalResponse.getOrDefault(TrustServiceClient.PN_STATUS, null))
                .requestId((String) evalResponse.get(TrustServiceClient.PN_REQUEST_ID));
        log.debug("evaluateIatProofInvitation.exit; returning: {}", accessResponseDto);
        return accessResponseDto;
    }

    private Map<String, Object> evaluateIatProofInvitation(Map<String, Object> accessRequestMap) {
        Map<String, Object> evalResponse = trustServiceClient.evaluate(GET_IAT_PROOF_INVITATION, accessRequestMap);
        String requestId = (String) evalResponse.get(TrustServiceClient.PN_REQUEST_ID);
        initIatRequest(requestId, accessRequestMap);
        accessRequestMap.putAll(evalResponse);
        return accessRequestMap;
    }

    private Map<String, Object> iatRequestToMap(AccessRequestDto request) {
        Map<String, Object> map = new HashMap<>();
        List<String> scopes = Arrays.asList(request.getEntity().getScope().split(" "));
        map.put(OAuth2ParameterNames.SCOPE, scopes);
        map.put(IdTokenClaimNames.SUB, request.getEntity().getDid());
        map.put(IdTokenClaimNames.ISS, request.getSubject());
        map.put(TrustServiceClient.PN_NAMESPACE, TrustServiceClient.NS_ACCESS);
        return map;
    }
    
    private void initIatRequest(String requestId, Map<String, Object> evalRequest) {
        claimsCache.put(requestId, evalRequest);
    }

    public AccessResponseDto evaluateIatProofResult(String requestId) {
        log.debug("evaluateIatProofResult.enter; got request: {}", requestId);
        Map<String, Object> evalRequest =  Collections.singletonMap(TrustServiceClient.PN_REQUEST_ID, requestId);
        Map<String, Object> evalResponse = trustServiceClient.evaluate(GET_IAT_PROOF_RESULT, evalRequest);
        AccessResponseDto accessResponseDto = mapToIatAccessResponse(evalResponse);
        if (accessResponseDto == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "request not found: " + requestId); 
        }

        if (accessResponseDto.getStatus() == AccessRequestStatusDto.ACCEPTED) {
            Map<String, Object> regResponse = iamClient.registerIam(accessResponseDto.getSubject(), List.of(redirectUri));
            String iat = (String) regResponse.get(PN_TOKEN);
            accessResponseDto.setInitialAccessToken(iat);
        }
        log.debug("evaluateIatProofResult.exit; returning status: {}", accessResponseDto.getStatus());
        return accessResponseDto;
    }

    public Map<String, Object> getIatProofClaims(String subjectId, String scope, Map<String, Object> params) {
        log.debug("getIatProofClaims.enter; got params: {}", params);
        Map<String, Object> iatClaims = claimsCache.get(subjectId);
        if (iatClaims == null) {
            List<String> scopes = Arrays.asList(scope.split(" "));
            params.put(OAuth2ParameterNames.SCOPE, scopes);
            iatClaims = evaluateIatProofInvitation(params);
        } else if (!iatClaims.containsKey(TrustServiceClient.PN_STATUS)) {
            iatClaims = loadTrustedClaims(GET_IAT_PROOF_RESULT, subjectId, null);
            //addAuthData(requestId, iatClaims);
        }
        log.debug("getIatProofClaims.exit; returning: {}", iatClaims.size());
        return iatClaims;
    }
    
    private AccessResponseDto mapToIatAccessResponse(Map<String, Object> map) {
        String requestId = (String) map.get(TrustServiceClient.PN_REQUEST_ID);
        if (requestId == null) {
            // throw error?
            log.info("mapToIatAccessResponse; no requestId found in IAT response: {}", map);
            return null;
        }

        String entity = null;
        String subject = null;
        Collection<String> scopes = null;
        Map<String, Object> iatRequest = claimsCache.get(requestId);
        if (iatRequest == null) {
            log.info("mapToIatAccessResponse; no data found for requestId: {}", requestId);
            return null;
        } 
        entity = (String) iatRequest.get(IdTokenClaimNames.ISS);
        subject = (String) iatRequest.get(IdTokenClaimNames.SUB);
        scopes = (Collection<String>) iatRequest.get(OAuth2ParameterNames.SCOPE);
        
        // update request with new data?
        // remove request after acceptance?

        return new AccessResponseDto().subject(entity)
                .entity(new ServiceAccessScopeDto()
                        .scope(scopes == null ? null : scopes.stream().collect(Collectors.joining(" ")))
                        .did(subject)) 
                .status((AccessRequestStatusDto) map.getOrDefault(TrustServiceClient.PN_STATUS, null))
                .requestId(requestId);
                //.initialAccessToken((String) map.getOrDefault("iat", null))
                //.policyEvaluationResult(map.getOrDefault("policyEvaluationResult", null));
    }

}
