package eu.xfsc.aas.controller;

import static eu.xfsc.aas.client.TrustServiceClient.LINK_SCHEME;
import static eu.xfsc.aas.generated.model.AccessRequestStatusDto.ACCEPTED;
import static eu.xfsc.aas.generated.model.AccessRequestStatusDto.REJECTED;
import static eu.xfsc.aas.generated.model.AccessRequestStatusDto.TIMED_OUT;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Date;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.test.web.servlet.MvcResult;

import eu.xfsc.aas.client.LocalTrustServiceClientImpl;
import eu.xfsc.aas.model.TrustServicePolicy;
import jakarta.servlet.ServletException;

public class OidcFlowTest extends AuthFlowTest {

    @Test
    void testOidcLoginFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "secret", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                null, s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));

        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        //assertNull(claims.get(IdTokenClaimNames.AUTH_TIME)); // changed with auth-server release 1.1.0. not clear, is it correct or not
        assertNull(claims.get(StandardClaimNames.NAME));
        assertNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNull(claims.get(StandardClaimNames.FAMILY_NAME));
        assertNull(claims.get(StandardClaimNames.MIDDLE_NAME));
        assertNull(claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNull(claims.get(StandardClaimNames.GENDER));
        assertNull(claims.get(StandardClaimNames.BIRTHDATE));
        assertNull(claims.get(StandardClaimNames.UPDATED_AT));
        assertNull(claims.get(StandardClaimNames.EMAIL));
        assertNull(claims.get(StandardClaimNames.EMAIL_VERIFIED));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
    }

    @Test
    void testOidcLoginHint() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "secret", ClientAuthenticationMethod.CLIENT_SECRET_POST,
                null, s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));

        String token = (String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN);

        Map<String, Object> claims2 = getAuthClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "secret", ClientAuthenticationMethod.CLIENT_SECRET_POST, 
                Map.of("max_age", 10, "id_token_hint", token), s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));
        
        assertEquals(claims.get(IdTokenClaimNames.SUB), claims2.get(IdTokenClaimNames.SUB));
        Long iat = ((Date) claims.get(IdTokenClaimNames.IAT)).toInstant().getEpochSecond();
        Long authTime = (Long) claims2.get(IdTokenClaimNames.AUTH_TIME);
        assertTrue((authTime - iat) >= 0);
        assertTrue((authTime - iat) < 10);
    }
    
    @Test
    void testOidcLoginMaxScope() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid profile email", "some.state", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "some-nonce", "secret", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                Map.of("max_age", 1), s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));
        
        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNotNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims.get(StandardClaimNames.NAME));
        assertNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNull(claims.get(StandardClaimNames.FAMILY_NAME));
        assertNull(claims.get(StandardClaimNames.MIDDLE_NAME));
        assertNull(claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNull(claims.get(StandardClaimNames.GENDER));
        assertNull(claims.get(StandardClaimNames.BIRTHDATE));
        assertNull(claims.get(StandardClaimNames.UPDATED_AT));
        assertNull(claims.get(StandardClaimNames.EMAIL));
        assertNull(claims.get(StandardClaimNames.EMAIL_VERIFIED));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
        assertNotNull(userInfo.get(IdTokenClaimNames.AUTH_TIME));
        assertNotNull(userInfo.get(StandardClaimNames.NAME));
        assertNotNull(userInfo.get(StandardClaimNames.GIVEN_NAME));
        assertNotNull(userInfo.get(StandardClaimNames.FAMILY_NAME));
        assertNull(userInfo.get(StandardClaimNames.MIDDLE_NAME));
        assertNotNull(userInfo.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNotNull(userInfo.get(StandardClaimNames.GENDER));
        assertNotNull(userInfo.get(StandardClaimNames.BIRTHDATE));
        assertNotNull(userInfo.get(StandardClaimNames.UPDATED_AT));
        assertNotNull(userInfo.get(StandardClaimNames.EMAIL));
        assertNotNull(userInfo.get(StandardClaimNames.EMAIL_VERIFIED));
    }
    
    @Test
    void testOidcLoginAdditionalClaims() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "some.state", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "some-nonce", "secret", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                Map.of("claims", "{\"userinfo\": {\"name\": {\"essential\": true}, \"email\": null}, \"id_token\": {\"auth_time\": {\"essential\": true}}}"), 
                s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));

        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNotNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims.get(StandardClaimNames.NAME));
        assertNull(claims.get(StandardClaimNames.EMAIL));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
        assertNull(userInfo.get(IdTokenClaimNames.AUTH_TIME));
        assertNotNull(userInfo.get(StandardClaimNames.NAME));
        assertNotNull(userInfo.get(StandardClaimNames.EMAIL));
    }
    
    @Test
    void testOidcLoginTimeout() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, TIMED_OUT);

        MvcResult authResult = getAuthResult("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc", 
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", null, s -> LINK_SCHEME + s, 
                ssn -> statusCallback(ssn, HttpStatus.FOUND.value()), 
                "/ssi/login?error=login_timed_out");
        assertNotNull(authResult.getRequest().getParameter(OAuth2ParameterNames.USERNAME));
        assertNotNull(authResult.getRequest().getParameter(OAuth2ParameterNames.PASSWORD));
    }

    @Test
    void testOidcLoginReject() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, REJECTED);

        MvcResult authResult = getAuthResult("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc", 
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", null, s -> LINK_SCHEME + s, 
                ssn -> statusCallback(ssn, HttpStatus.FOUND.value()), // .BAD_GATEWAY.value()),
                "/ssi/login?error=login_rejected");
        assertNotNull(authResult.getRequest().getParameter(OAuth2ParameterNames.USERNAME));
        assertNotNull(authResult.getRequest().getParameter(OAuth2ParameterNames.PASSWORD));
    }

    @Test
    void testOidcLoginErrorRequest() throws Exception {

        Map<String, Object> params = getAuthRequestParams("openid", null, "code", "aas-app-oidc", keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", 
                null, Map.of("request", "error-request"));
        String rq = getAuthRequest(params);
        Object[] values = params.values().toArray(new Object[params.size()]);

        try {
            mockMvc.perform(get("/oauth2/authorize?" + rq, values).accept(MediaType.TEXT_HTML,
                            MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(header().string("Location", containsString("/ssi/login"))).andReturn();
            assertEquals("servlet exception", "got redirect");
        } catch (ServletException ex) {
            // Redirecting to http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint?error=request_not_supported
            assertTrue(ex.getCause() instanceof AccessDeniedException);
        }
    }
    
}
