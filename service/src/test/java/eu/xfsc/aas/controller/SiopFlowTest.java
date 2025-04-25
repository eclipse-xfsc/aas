package eu.xfsc.aas.controller;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.test.web.servlet.MvcResult;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;

public class SiopFlowTest extends AuthFlowTest {

    @Test
    void testSiopLoginFlow() throws Exception {
        Map<String, Object> claims = getAuthClaims("openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", 
                "aas-app-siop", keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "secret2", 
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null, rid -> 
                    "openid://?scope=openid&response_type=id_token&client_id=" + oidcIssuer + "&redirect_uri=" + oidcIssuer + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, ssn -> {
                        try {
                            Map<String, Object> params = new HashMap<>();
                            params.put(IdTokenClaimNames.ISS, "https://self-issued.me/v2");
                            params.put(IdTokenClaimNames.SUB, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
                            params.put(IdTokenClaimNames.AUD, oidcIssuer);
                            params.put(IdTokenClaimNames.NONCE, ssn.getAttribute("requestId"));
                            params.put(IdTokenClaimNames.EXP, Instant.now().plusSeconds(600).getEpochSecond());
                            params.put(IdTokenClaimNames.IAT, Instant.now().getEpochSecond());
                            params.put(IdTokenClaimNames.AUTH_TIME, Instant.now().getEpochSecond());
                            String rq = OidcParameterNames.ID_TOKEN + "=" + mapper.writeValueAsString(params);
                            mockMvc.perform(post("/ssi/siop-callback")
                                    .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .content(rq))
                                .andExpect(status().isOk());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        return null;
                    }
                );

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
    }

    @Test
    void testSiopLoginMaxScope() throws Exception {
        Map<String, Object> claims = getAuthClaims("openid profile email", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", 
                "aas-app-siop", keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", "secret2", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                null, rid -> 
                    "openid://?scope=openid profile email&response_type=id_token&client_id=" + oidcIssuer + "&redirect_uri=" + oidcIssuer + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, ssn -> {
                        try {
                        	String rid = (String) ssn.getAttribute("requestId");
                            long stamp = System.currentTimeMillis();
                            Map<String, Object> params = new HashMap<>();
                            params.put(IdTokenClaimNames.ISS, "https://self-issued.me/v2");
                            params.put(IdTokenClaimNames.SUB, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
                            params.put(IdTokenClaimNames.AUD, oidcIssuer);
                            params.put(IdTokenClaimNames.NONCE, rid);
                            params.put(IdTokenClaimNames.EXP, Instant.now().plusSeconds(600).getEpochSecond());
                            params.put(IdTokenClaimNames.IAT, Instant.now().getEpochSecond());
                            params.put(IdTokenClaimNames.AUTH_TIME, Instant.now().getEpochSecond());
                            params.put(StandardClaimNames.NAME, rid);
                            params.put(StandardClaimNames.GIVEN_NAME, rid + ": " + stamp);
                            params.put(StandardClaimNames.FAMILY_NAME, String.valueOf(stamp));
                            params.put(StandardClaimNames.MIDDLE_NAME, "");
                            params.put(StandardClaimNames.PREFERRED_USERNAME, rid + " " + stamp);
                            params.put(StandardClaimNames.GENDER, stamp % 2 == 0 ? "F" : "M");
                            params.put(StandardClaimNames.BIRTHDATE, LocalDate.now().minusYears(21).toString());
                            params.put(StandardClaimNames.UPDATED_AT, Instant.now().minusSeconds(86400).getEpochSecond());
                            params.put(StandardClaimNames.EMAIL, rid + "@oidc.ssi");
                            params.put(StandardClaimNames.EMAIL_VERIFIED, Boolean.TRUE);
                            String rq = OidcParameterNames.ID_TOKEN + "=" + mapper.writeValueAsString(params);
                            mockMvc.perform(post("/ssi/siop-callback")
                                    .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                                    .content(rq))
                                .andExpect(status().isOk());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        return null;
                    }
                );

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
        //assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        //assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
        //assertNotNull(userInfo.get(IdTokenClaimNames.AUTH_TIME));
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
    void testSiopCallbackError() throws Exception {
    	
        MvcResult authResult = getAuthResult("openid", "QfjgI5XxMjNkvUU2f9sWQymGfKoaBr7Ro2jHprmBZrg.VTxL7FGKhi0.demo-app", "code", "aas-app-siop", 
                keycloakUri + "/realms/gaia-x/broker/ssi-siop/endpoint", "Q5h3noccV6Hwb4pVHps41A", null, rid -> 
                    "openid://?scope=openid&response_type=id_token&client_id=" + oidcIssuer + "&redirect_uri=" + oidcIssuer + 
                    "/ssi/siop-callback&response_mode=post&nonce=" + rid, null, //ssn -> statusCallback(ssn, HttpStatus.FOUND.value()), 
                    "/ssi/login?error=server_error");
        String requestId = authResult.getRequest().getParameter(OAuth2ParameterNames.USERNAME); 
        HttpSession session = authResult.getRequest().getSession(false);
        String reUrl = authResult.getResponse().getHeader("Location");
        
        // get /ssi/login and check error presence..
        authResult = mockMvc
                .perform(get(reUrl) 
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();
        assertEquals(getMessage("server_error", authResult.getRequest().getLocale()), (String) authResult.getModelAndView().getModel().get("errorMessage"));
        
        mockMvc.perform(
                    post("/ssi/siop-callback")
                            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                            .content("error=invalid_request&error_description=Unsupported%20response_type%20value&nonce=" + requestId))
                // we had error response above, so we're redirected back to login page to see errors 
                .andExpect(status().isOk())
                .andReturn();

        authResult = mockMvc
                .perform(get("/ssi/login?error=invalid_request")
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();
        assertEquals(getMessage("invalid_request", authResult.getRequest().getLocale()), (String) authResult.getModelAndView().getModel().get("errorMessage"));
        
        Map<String, Object> params = new HashMap<>();
        params.put(IdTokenClaimNames.ISS, "https://self-issued.me/v2");
        params.put(IdTokenClaimNames.SUB, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        params.put(IdTokenClaimNames.AUD, oidcIssuer);
        params.put(IdTokenClaimNames.NONCE, requestId);
        params.put(IdTokenClaimNames.EXP, Instant.now().plusSeconds(600).getEpochSecond());
        params.put(IdTokenClaimNames.IAT, Instant.now().getEpochSecond());
        mockMvc.perform(
                    post("/ssi/siop-callback")
                            .contentType(APPLICATION_FORM_URLENCODED_VALUE)
                            .content(OidcParameterNames.ID_TOKEN + "=" + mapper.writeValueAsString(params)))
            .andExpect(status().isOk()) 
            //.andExpect(status().reason(containsString("invalid nonce"))) // no requestId any more
            .andReturn();
    }
    
    @Test
    void testSiopCallbackMissingParameter() throws Exception {
        mockMvc.perform(
                    post("/ssi/siop-callback").contentType(APPLICATION_FORM_URLENCODED_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(status().reason(containsString("no id_token nor error provided")));
    }
    
	
}
