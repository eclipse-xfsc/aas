package eu.xfsc.aas.controller;

import static eu.xfsc.aas.client.TrustServiceClient.LINK_SCHEME;
import static eu.xfsc.aas.generated.model.AccessRequestStatusDto.ACCEPTED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import eu.xfsc.aas.client.LocalTrustServiceClientImpl;
import eu.xfsc.aas.model.TrustServicePolicy;

public class TokenEndpointTest extends AuthFlowTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Value("${aas.oidc.issuer}")
    private String oidcIssuer;

    @Test
    void testClientCredentialsFlow() throws Exception {
    	String clientId = "id";
    	String secret = "secret";
        String bearer = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
        mockMvc.perform(post("/oauth2/token")
                .header("Authorization", "Basic " + bearer)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()))
            .andExpect(status().isUnauthorized());

    	clientId = "aas-app-oidc";
        bearer = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                .header("Authorization", "Basic " + bearer)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()))
            .andExpect(status().isOk())
            .andReturn();

        String token = result.getResponse().getContentAsString();
        Map<String, Object> tokenFields = new JacksonJsonParser().parseMap(token);
        
        assertNotNull(tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertNotNull(tokenFields.get(OAuth2ParameterNames.EXPIRES_IN));
        assertNotNull(tokenFields.get(OAuth2ParameterNames.TOKEN_TYPE));
        assertTrue(((Integer) tokenFields.get(OAuth2ParameterNames.EXPIRES_IN)) > 250); // default is 300
        assertEquals("Bearer", tokenFields.get(OAuth2ParameterNames.TOKEN_TYPE));
        
        String accessToken = tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        JWT jwt = JWTParser.parse(accessToken);
        assertEquals(clientId, jwt.getJWTClaimsSet().getSubject());
        assertEquals(oidcIssuer, jwt.getJWTClaimsSet().getIssuer());
    }

    @Test
    void testPkceLoginFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);
        
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(challenge.getBytes(StandardCharsets.US_ASCII));
		String hash = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

        Map<String, Object> claims = getAuthClaims("profile openid", "b43e24c9285542418a57b8fc00d283f8", "code", "gxfs-demo",
                "https://demo.gxfs.dev", "sxXudRdJkvAp5kh_QqJQxzij2lDDD4ofb4Fx_rFn7x4", null, ClientAuthenticationMethod.NONE,
                Map.of("code_challenge_method", "S256", "code_challenge", hash), 
                s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));
        
        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));

        Map<String, Object> userInfo = getUserInfo((String) claims.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertEquals(claims.get(IdTokenClaimNames.ISS), userInfo.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), userInfo.get(IdTokenClaimNames.SUB));
    }
   
    @Test
    void testRefreshTokenFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getAuthClaims("openid", "HAQlByTNfgFLmnoY38xP9pb8qZtZGu2aBEyBao8ezkE.bLmqaatm4kw.demo-app", "code", "aas-app-oidc",
                keycloakUri + "/realms/gaia-x/broker/ssi-oidc/endpoint", "fXCqL9w6_Daqmibe5nD7Rg", "secret", ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                null, /*Map.of("max_age", 5),*/ s -> LINK_SCHEME + s, ssn -> statusCallback(ssn, HttpStatus.FOUND.value()));

        // check claims..
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNotNull(claims.get(OAuth2ParameterNames.REFRESH_TOKEN));
        String accessToken = claims.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        String refreshToken = claims.get(OAuth2ParameterNames.REFRESH_TOKEN).toString();
        JWT jwt = JWTParser.parse(accessToken);
        claims = jwt.getJWTClaimsSet().getClaims();
        
		Thread.sleep(5000);
        // now login with refresh token and get renewed access token 
    	String clientId = "aas-app-oidc";
    	String secret = "secret";
        String bearer = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                .header("Authorization", "Basic " + bearer)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue())
                .param(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken))
            .andExpect(status().isOk())
            .andReturn();

        String token = result.getResponse().getContentAsString();
        Map<String, Object> tokenFields = new JacksonJsonParser().parseMap(token);
        String accessToken2 = tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        assertNotEquals(accessToken, accessToken2);
        jwt = JWTParser.parse(accessToken2);
        Map<String, Object> claims2 = jwt.getJWTClaimsSet().getClaims();
        assertEquals(claims.get(IdTokenClaimNames.ISS), claims2.get(IdTokenClaimNames.ISS));
        assertEquals(claims.get(IdTokenClaimNames.SUB), claims2.get(IdTokenClaimNames.SUB));
        Date iat = (Date) claims.get(IdTokenClaimNames.IAT);
        Date iat2 = (Date) claims2.get(IdTokenClaimNames.IAT);
        assertTrue(iat2.after(iat));
        Date exp = (Date) claims.get(IdTokenClaimNames.EXP);
        Date exp2 = (Date) claims2.get(IdTokenClaimNames.EXP);
        assertTrue(exp.before(exp2));
    }
    
}



