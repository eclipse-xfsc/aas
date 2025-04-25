package eu.xfsc.aas.service;

import static eu.xfsc.aas.model.TrustServicePolicy.GET_LOGIN_PROOF_INVITATION;
import static eu.xfsc.aas.model.TrustServicePolicy.GET_LOGIN_PROOF_RESULT;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_REQUEST;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_SCOPE;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import javax.imageio.ImageIO;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import eu.xfsc.aas.client.InvitationServiceClient;
import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.generated.model.AccessRequestStatusDto;
import eu.xfsc.aas.model.SsiClientCustomClaims;
import eu.xfsc.aas.properties.ScopeProperties;

@Slf4j
@Service
public class SsiBrokerService extends SsiClaimsService {

    @Value("${aas.oidc.issuer}")
    private String oidcIssuer;
    @Value("${aas.oidc.static-scopes}")
    private Set<String> staticScopes;
    @Value("${aas.siop.clock-skew}")
    private Duration clockSkew;
    @Value("${aas.siop.issuer}")
    private String siopIssuer;

    private final ScopeProperties scopeProperties;
    private final InvitationServiceClient invitationClient;
    private final SsiClientsRepository ssiClientsRepository;
    
    public SsiBrokerService(TrustServiceClient trustServiceClient, ScopeProperties scopeProperties, InvitationServiceClient invitationService, 
    		SsiClientsRepository ssiClientsRepository) {
        super(trustServiceClient);
        this.scopeProperties = scopeProperties;
        this.invitationClient = invitationService;
        this.ssiClientsRepository = ssiClientsRepository;
    }
    
    public String oidcAuthorize(Map<String, Object> model) {
        log.debug("oidcAuthorize.enter; got model: {}", model);

        Map<String, Object> params = new HashMap<>();
        params.put(TrustServiceClient.PN_NAMESPACE, TrustServiceClient.NS_LOGIN);

        Set<String> scopes = processScopes(model);
        if (staticScopes != null && !staticScopes.isEmpty()) {
            params.put(OAuth2ParameterNames.SCOPE, staticScopes);
        } else {
            params.put(OAuth2ParameterNames.SCOPE, scopes);
        }
        
        // they can be provided in re-login scenario..
        processAttribute(model, params, IdTokenClaimNames.SUB);
        processAttribute(model, params, "max_age");
        // check with local cache??

        Map<String, Object> result = trustServiceClient.evaluate(GET_LOGIN_PROOF_INVITATION, params);
        String link = (String) result.get(TrustServiceClient.PN_LINK);
        String requestId = (String) result.get(TrustServiceClient.PN_REQUEST_ID);
        Map<String, Object> data = initAuthRequest(requestId, scopes, (String) model.get("clientId"), link);
        log.debug("oidcAuthorize; OIDC request {} stored: {}", requestId, data);

        String mobileUrl = invitationClient.getMobileInvitationUrl(link);
        log.debug("oidcAuthorize; mobile URL translated in {} ", mobileUrl);
        // encode link otherwise it'll not pass security check
        String qrUrl = "/ssi/qr/" + Base64.getUrlEncoder().encodeToString(link.getBytes());
        model.put("qrUrl", qrUrl);
        model.put(TrustServiceClient.PN_REQUEST_ID, requestId);
        model.put("mobileUrl", mobileUrl);

        log.debug("oidcAuthorize.exit; returning model: {}", model);
        return requestId;
    }

    public String siopAuthorize(Map<String, Object> model) {
        log.debug("siopAuthorize.enter; got model: {}", model);

        Set<String> scopes = processScopes(model);

        String requestId = UUID.randomUUID().toString();
        String link = buildRequestString(scopes, requestId);
        Map<String, Object> data = initAuthRequest(requestId, scopes, (String) model.get("clientId"), link);
        log.debug("siopAuthorize; SIOP request {} stored: {}", requestId, data);
        
        String qrUrl = "/ssi/qr/" + Base64.getUrlEncoder().encodeToString(link.getBytes());
        model.put("qrUrl", qrUrl);
        model.put(TrustServiceClient.PN_REQUEST_ID, requestId);

        log.debug("siopAuthorize.exit; returning model: {}", model);
        return requestId;
    }
    
    public RegisteredClientRepository getClientsRepository() {
    	return ssiClientsRepository;
    }

    private Set<String> processScopes(Map<String, Object> model) {
        Set<String> scopes = new HashSet<>();
        Object o = model.get(OAuth2ParameterNames.SCOPE);
        if (o != null) {
            Arrays.stream((String[]) o).forEach(ss -> {
                Arrays.asList(ss.split(" ")).stream().forEach(s -> {
                    if (scopeProperties.getScopes().containsKey(s)) {
                        scopes.add(s);
                    }
                });
            });
        }
        return scopes;
    }

    private void processAttribute(Map<String, Object> model, Map<String, Object> params, String attribute) {
        Object o = model.get(attribute);
        if (o != null) {
            params.put(attribute, o);
        }
    }

    private String buildRequestString(Set<String> scopes, String requestId) {
        List<String> params = new ArrayList<>();
        params.add(OAuth2ParameterNames.SCOPE + "=" + String.join(" ", scopes));
        params.add(OAuth2ParameterNames.RESPONSE_TYPE + "=" + OidcParameterNames.ID_TOKEN);
        params.add(OAuth2ParameterNames.CLIENT_ID +  "=" + oidcIssuer);
        params.add(OAuth2ParameterNames.REDIRECT_URI + "=" + oidcIssuer + "/ssi/siop-callback");
        params.add("response_mode=post");
        params.add(OidcParameterNames.NONCE + "=" + requestId);
        return "openid://?" + String.join("&", params);
    }

    public byte[] getQR(String elink) {
        // the incoming link is encoded, we must decode it first
        log.debug("getQR.enter; got elink: {}", elink);
        String link = new String(Base64.getUrlDecoder().decode(elink));
        QRCodeWriter barcodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = null;
        try {
            bitMatrix = barcodeWriter.encode(link, BarcodeFormat.QR_CODE, 600, 600);
        } catch (WriterException e) {
            log.error("getQR.error; QR data generation failed", e);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            ImageIO.write(MatrixToImageWriter.toBufferedImage(bitMatrix), "png", baos);
        } catch (IOException e) {
            log.error("getQR.error; Failed to generate image from QR data", e);
        }
        log.debug("getQR.exit; returning image for link: {}", link);
        return baos.toByteArray();
    }

    public void processSiopLoginResponse(Map<String, Object> response) {
        log.debug("processSiopLoginResponse.enter; got response: {}", response);
        String requestId = (String) response.get(IdTokenClaimNames.NONCE);
        if (requestId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: invalid nonce"); 
        } 
        Boolean valid = isValidRequest(requestId);
        if (valid == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: invalid nonce");
        }
        if (!valid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: request expired");
        }
        
        String error = (String) response.get(OAuth2ParameterNames.ERROR);
        if (error == null) {
            Collection<String> requestedScopes = (Collection<String>) claimsCache.get(requestId).get(OAuth2ParameterNames.SCOPE);
            Set<String> requestedClaims = scopeProperties.getScopes().entrySet().stream()
                    .filter(e -> requestedScopes.contains(e.getKey())).flatMap(e -> e.getValue().stream()).collect(Collectors.toSet());
            // special handling for auth_time..
            requestedClaims.remove(IdTokenClaimNames.AUTH_TIME);
            
            DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(new JWTClaimsSet.Builder()
                .issuer(siopIssuer)
                .audience(oidcIssuer)
                .build(), requestedClaims);
            try {
                verifier.verify(JWTClaimsSet.parse(response), null);
            } catch(ParseException | BadJWTException ex) {
                log.info("processSiopLoginResponse.error; {}", ex.getMessage());
                claimsCache.remove(requestId);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: " + ex.getMessage()); 
            }
                
            String issuer = (String) response.get(IdTokenClaimNames.ISS);
            String subject = (String) response.get(IdTokenClaimNames.SUB);
            // should be the same..
            if (!issuer.equals(subject)) {
                log.info("processSiopLoginResponse; issuer and subject have different values");
            }
                
            try {
                subject = new String(Base64.getUrlDecoder().decode(subject));
                log.debug("processSiopLoginResponse; subject: {}", subject);
            } catch (Exception ex) {
                log.debug("processSiopLoginResponse; subject is not base64-encoded: {}", subject);
            }
        }
        addAuthData(requestId, response);
        log.debug("processSiopLoginResponse.exit; error processed: {}", error != null);
    }
    
    private Map<String, Object> initAuthRequest(String requestId, Set<String> scopes, String clientId, String link) {
        Map<String, Object> data = new HashMap<>();
        data.put("request_time", Instant.now());
        data.put(OAuth2ParameterNames.SCOPE, scopes);
        data.put("client_id", clientId);
        data.put("auth_link", link);
        claimsCache.put(requestId, data);
        //Map<String, Object> existing = claimsCache.put(requestId, data);
        //if (existing != null) {
        //    log.warn("addAuthRequest; data for request {} alreday stored: {}", requestId, existing);
        //}
        return data;
    }
    
    public boolean setAdditionalParameters(String requestId, Map<String, Object> additionalParams) {
        log.debug("setAdditionalParameters.enter; got request: {} params: {}", requestId, additionalParams);
        boolean result = true;
        Map<String, Object> request = claimsCache.get(requestId);
        if (request == null) {
            // throw error?
            result = false;
        } else {
            request.put("additional_parameters", additionalParams);
            claimsCache.put(requestId, request);
        }
        log.debug("setAdditionalParameters.exit; updated: {}, cacheSize: {}", result, claimsCache.estimatedSize());
        return result;
        
    }
    
    private Map<String, Object> addAuthData(String requestId, Map<String, Object> data) {
        log.debug("addAuthData.enter; got request: {} claims size: {}", requestId, data.size());
        boolean found = true;
        Map<String, Object> request = claimsCache.get(requestId);
        if (request == null) {
            // throw error?
            found = false;
        } else {
        	request.forEach((k, v) -> data.putIfAbsent(k, v));
            //data.putAll(request);
        }
        claimsCache.put(requestId, data);
        log.debug("addAuthData.exit; found: {}, stored claims: {}, cacheSize: {}", found, data.size(), claimsCache.estimatedSize());
        return data;
    }

    private Boolean isValidRequest(String requestId) {
        Map<String, Object> request = claimsCache.get(requestId);
        if (request == null) {
            return null;
        }
        
        Instant requestTime = (Instant) request.get("request_time");
        return requestTime != null && requestTime.isBefore(Instant.now()) && requestTime.isAfter(Instant.now().minus(clockSkew));
    }
    
    public Map<String, Object> getSubjectClaims(String subjectId, Collection<String> requestedScopes) {
        log.debug("getSubjectClaims.enter; got subject: {}, scopes: {}", subjectId, requestedScopes);
        Map<String, Object> userClaims = getUserClaims(subjectId, true, requestedScopes, null);
        log.debug("getSubjectClaims.exit; returning: {}", userClaims == null ? null : userClaims.keySet());
        return userClaims;
    }

    public Map<String, Object> getUserClaims(String requestId, boolean required, Collection<String> requestedScopes, Collection<String> requestedClaims) {
        Map<String, Object> userClaims = getUserClaims(requestId, required);
        if (userClaims == null) {
            log.debug("getUserClaims; no claims found, cache size is: {}", claimsCache.estimatedSize()); 
            return null;
        }
        
        return filterUserClaims(userClaims, requestedScopes, requestedClaims);
    }
    
    public Map<String, Object> getUserClaims(String requestId, boolean required) {
    	Map<String, Object> tsaClaims = null;
        Map<String, Object> authClaims = claimsCache.get(requestId); 
        if (!isClaimsLoaded(authClaims)) {
            log.info("getUserClaims; no claims found for request: {}, required: {}", requestId, required);
            if (required) {
                tsaClaims = getTrustedClaims(GET_LOGIN_PROOF_RESULT, requestId, getClientRestrictions(authClaims));
            } else {
            	authClaims = null;
            }
        }
        if (tsaClaims != null) {
            AccessRequestStatusDto sts = (AccessRequestStatusDto) tsaClaims.get(TrustServiceClient.PN_STATUS);
            if (sts != AccessRequestStatusDto.PENDING || authClaims == null) {
            	authClaims = addAuthData(requestId, tsaClaims);
            } else {
            	Instant rt = (Instant) authClaims.get("request_time");
            	long dm = getTimeout();
            	Instant tm = rt.plusMillis(dm); //getTimeout());
            	if (tm.isBefore(Instant.now())) {
                    log.warn("getUserClaims; detected timeout at: {}, rt: {}, dm: {}", tm, rt, dm);
            		authClaims.put(TrustServiceClient.PN_STATUS, AccessRequestStatusDto.TIMED_OUT);
            	} else {
            		authClaims.put(TrustServiceClient.PN_STATUS, sts);
            	}
            }
        }
        return authClaims;
    }
    
    public Set<String> getUserScopes(String requestId) {
        Map<String, Object> userClaims = claimsCache.get(requestId);
        if (userClaims == null) {
            log.warn("getUserScopes; no claims found for request: {}", requestId);
            throw new OAuth2AuthenticationException(INVALID_REQUEST);
        }
        
        Set<String> scopes = (Set<String>) userClaims.get(OAuth2ParameterNames.SCOPE);
        if (scopes == null) {
            log.warn("getUserScopes; no scopes found for request: {}", requestId);
            throw new OAuth2AuthenticationException(INVALID_SCOPE);
        }

        //Map<String, String> claims = scopeProperties.getScopes().entrySet().stream().map(e -> e.getValue())
        return scopes; //userClaims.keySet().stream().filter(c -> scopeProperties.getScopes().entrySet() .values().contains(c)).collect(Collectors.toSet());
    }
    
    public Map<String, Object> getAdditionalParameters(String requestId) {
        Map<String, Object> userClaims = claimsCache.get(requestId);
        if (userClaims == null) {
            // log it..
            return null;
        }
        Map<String, Object> params = (Map<String, Object>) userClaims.get("additional_parameters");
        if (params == null) {
            return null;
        }
        return new HashMap<>(params);
    }

    public Map<String, Object> loadSubjectClaims(String subjectId, Collection<String> requestedScopes) {
        log.debug("getSubjectClaims.enter; got subject: {}, scopes: {}", subjectId, requestedScopes);
        Map<String, Object> userClaims;
        try {
            userClaims = loadUserClaims(subjectId);
            if (userClaims == null) {
                log.debug("getUserClaims; no claims found, cache size is: {}", claimsCache.estimatedSize()); 
            } else {            
                userClaims = filterUserClaims(userClaims, requestedScopes, null);
            }
        } catch (OAuth2AuthenticationException ex) {
            userClaims = new HashMap<>();
            userClaims.put(OAuth2ParameterNames.SCOPE, requestedScopes.toArray(new String[0]));
            userClaims.put(IdTokenClaimNames.SUB, subjectId);
            oidcAuthorize(userClaims);
            String qrUrl = (String) userClaims.remove("qrUrl");
            qrUrl = qrUrl.substring(8); // remove /ssi/qr/ prefix
            String link = new String(Base64.getUrlDecoder().decode(qrUrl));
            userClaims.put(TrustServiceClient.PN_LINK, link);
        }
        log.debug("getSubjectClaims.exit; returning: {}", userClaims == null ? null : userClaims.keySet());
        return userClaims;
    }
 
    private Map<String, Object> filterUserClaims(Map<String, Object> userClaims, Collection<String> requestedScopes, Collection<String> requestedClaims) {
        // return claims which corresponds to requested scopes only..
        Set<String> scopedClaims;
        if (requestedScopes == null) {
            scopedClaims = new HashSet<>();
        } else {
            scopedClaims = scopeProperties.getScopes().entrySet().stream()
                .filter(e -> requestedScopes.contains(e.getKey())).flatMap(e -> e.getValue().stream()).collect(Collectors.toSet());
        }
        if (requestedClaims != null) {
            scopedClaims.addAll(requestedClaims);
        }
        return userClaims.entrySet().stream()
                .filter(e -> e.getValue() != null && scopedClaims.contains(e.getKey()) && !e.getValue().toString().isEmpty())
                .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()));
    	
    }

    private Map<String, Object> loadUserClaims(String requestId) {
        Map<String, Object> userClaims = claimsCache.get(requestId); 
        if (!isClaimsLoaded(userClaims)) {
            userClaims = loadTrustedClaims(GET_LOGIN_PROOF_RESULT, requestId, getClientRestrictions(userClaims));
        }
        if (userClaims != null) {
            AccessRequestStatusDto sts = (AccessRequestStatusDto) userClaims.get(TrustServiceClient.PN_STATUS);
            if (sts != AccessRequestStatusDto.PENDING) {
            	addAuthData(requestId, userClaims);
            }        	
        }
        return userClaims;
    }
    
    private boolean isClaimsLoaded(Map<String, Object> claims) {
        return claims != null && (claims.containsKey(IdTokenClaimNames.SUB) || claims.containsKey(OAuth2ParameterNames.ERROR) ||
            claims.containsKey(StandardClaimNames.NAME) || claims.containsKey(StandardClaimNames.EMAIL));
    }
    
    private Map<String, Object> getClientRestrictions(Map<String, Object> claims) {
    	Map<String, Object> restrictions = null;
    	if (claims != null) {
    		String clientId = (String) claims.get("client_id");
    		if (clientId != null) {
    			RegisteredClient client = ssiClientsRepository.findByClientId(oidcIssuer);
    			if (client != null) {
    				restrictions = client.getClientSettings().getSetting(SsiClientCustomClaims.TSA_RESTRICTIONS);
    			}
    		}
    	}
    	return restrictions;
    }
    
}
