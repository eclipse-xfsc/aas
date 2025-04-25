package eu.xfsc.aas.controller;

import static eu.xfsc.aas.client.TrustServiceClient.LINK_SCHEME;
import static eu.xfsc.aas.generated.model.AccessRequestStatusDto.ACCEPTED;
import static eu.xfsc.aas.generated.model.AccessRequestStatusDto.REJECTED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.xfsc.aas.client.LocalTrustServiceClientImpl;
import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.model.TrustServicePolicy;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase.DatabaseProvider;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@AutoConfigureEmbeddedDatabase(provider = DatabaseProvider.ZONKY)
public class CipControllerTest {

    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<Map<String, Object>>() {
    };
    
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private TrustServiceClient trustServiceClient;

    @Test
    public void testCipRequestFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_IAT_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims = getUserClaims("sub=1234567890&scope=openid");
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertEquals("urn:id:1234567890", claims.get(IdTokenClaimNames.SUB));
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
        
        claims = getUserClaims("sub=1234567890&scope=openid profile email");
        assertNotNull(claims.get(IdTokenClaimNames.ISS));
        assertEquals("urn:id:1234567890", claims.get(IdTokenClaimNames.SUB));
        assertNotNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        assertNotNull(claims.get(StandardClaimNames.NAME));
        assertNotNull(claims.get(StandardClaimNames.GIVEN_NAME));
        assertNotNull(claims.get(StandardClaimNames.FAMILY_NAME));
        assertNull(claims.get(StandardClaimNames.MIDDLE_NAME));
        assertNotNull(claims.get(StandardClaimNames.PREFERRED_USERNAME));
        assertNotNull(claims.get(StandardClaimNames.GENDER));
        assertNotNull(claims.get(StandardClaimNames.BIRTHDATE));
        assertNotNull(claims.get(StandardClaimNames.UPDATED_AT));
        assertNotNull(claims.get(StandardClaimNames.EMAIL));
        assertNotNull(claims.get(StandardClaimNames.EMAIL_VERIFIED));
    }

    @Test
    public void testCipRequestNewClaims() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, REJECTED);

        Map<String, Object> claims = getUserClaims("sub=qwerty890&scope=openid");
        assertNotNull(claims.get("requestId"));
        String requestId = (String) claims.get("requestId");
        assertNotNull(claims.get("link"));
        assertEquals(LINK_SCHEME + "qwerty890", claims.get("link"));
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNull(claims.get(IdTokenClaimNames.ISS));
        assertNull(claims.get(IdTokenClaimNames.AUTH_TIME));
        
        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);

        Map<String, Object> claims2 = getUserClaims("sub=" + requestId + "&scope=openid");
        assertNotNull(claims2.get(IdTokenClaimNames.SUB));
        assertNotNull(claims2.get(IdTokenClaimNames.ISS));
        assertNotNull(claims2.get(IdTokenClaimNames.AUTH_TIME));
        assertNull(claims2.get("requestId"));
        assertNull(claims2.get("link"));
    }

    @Test
    public void testCipAccessClaims() throws Exception {

        Map<String, Object> claims = getUserClaims("namespace=Access&sub=did:qwerty123&scope=openid&iss=did:example567");
        assertNotNull(claims.get("requestId"));
        String requestId = (String) claims.get("requestId");
        assertNotNull(claims.get(IdTokenClaimNames.SUB));
        assertNotNull(claims.get(IdTokenClaimNames.ISS));

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_LOGIN_PROOF_RESULT, ACCEPTED);
        
        Map<String, Object> claims2 = getUserClaims("namespace=Access&sub=" + requestId + "&scope=openid");
        assertNotNull(claims2.get(IdTokenClaimNames.SUB));
        assertNotNull(claims2.get(IdTokenClaimNames.ISS));
        //assertNotNull(claims2.get(IdTokenClaimNames.AUTH_TIME));
    }
    
    private Map<String, Object> getUserClaims(String query) throws Exception {
        MvcResult result = mockMvc.perform(
                get("/cip/claims?" + query)
                    //.header("Authorization", "Bearer " + accessToken)
                    .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();
        return mapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
    }
    
}
