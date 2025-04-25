package eu.xfsc.aas.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase.DatabaseProvider;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(SpringExtension.class)
@AutoConfigureEmbeddedDatabase(provider = DatabaseProvider.ZONKY)
public class OidcDiscoveryTest {
    
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<Map<String, Object>>() {
    };

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;
    
    @Value("${aas.oidc.issuer}")
    private String oidcIssuer;

    @Test
    void getDiscoveryConfig_config() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk()).andReturn();

        Map<String, Object> config = objectMapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
        assertEquals(oidcIssuer, config.get("issuer").toString());
        
        assertEquals(oidcIssuer + "/oauth2/jwks", config.get("jwks_uri"));
        result = mockMvc.perform(get((String) config.get("jwks_uri")))
                .andExpect(status().isOk()).andReturn();
        Map<String, Object> keySet = objectMapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
        assertNotNull(keySet.get("keys"));
        assertEquals(2, ((Collection<?>) keySet.get("keys")).size());
    }
    
    @Test
    void getDiscoveryConfig_scopes() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk()).andReturn();

        List<String> supportedScopes = new ArrayList<>();

        objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("scopes_supported")
                .elements()
                .forEachRemaining(jsonNode -> supportedScopes.add(jsonNode.asText()));

        assertTrue(List.of("openid", "profile", "email", "protected").containsAll(supportedScopes));
    }

    @Test
    void getDiscoveryConfig_claims() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk()).andReturn();

        List<String> supportedClaims = new ArrayList<>();

        objectMapper
                .readTree(result.getResponse().getContentAsString())
                .get("claims_supported")
                .elements()
                .forEachRemaining(jsonNode -> supportedClaims.add(jsonNode.asText()));

        assertTrue(List.of("sub", "iss", "auth_time", "name", "given_name", "family_name", "middle_name", "preferred_username", "gender",
                "birthdate", "updated_at", "email", "email_verified", "read_access", "write_access").containsAll(supportedClaims));
    }

}

  
