package eu.xfsc.aas.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import eu.xfsc.aas.model.SsiClientCustomClaims;
import eu.xfsc.aas.service.SsiAuthorizationService;
import eu.xfsc.aas.service.SsiClientsRepository;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase.DatabaseProvider;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@AutoConfigureEmbeddedDatabase(provider = DatabaseProvider.ZONKY)
public class ClientRegistrationTest {

    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<Map<String, Object>>() {
    };
    
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private SsiClientsRepository clientsRepo;
    @Autowired
    private SsiAuthorizationService authService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void readClientTest() throws Exception {
    	String clientId = "aas-app-oidc";
    	String clientSecret = "secret";
    	Jwt jwt = buildJwt(clientId, "client.read");
        MvcResult result = mockMvc.perform(get("/connect/register?client_id={clientId}", clientId)
        		.with(jwt().jwt(jwt)))
                .andExpect(status().isOk()).andReturn();
        Map<String, Object> client = mapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
        assertEquals(clientId, client.get(OidcClientMetadataClaimNames.CLIENT_ID).toString());
        assertTrue(passwordEncoder.matches(clientSecret, client.get(OidcClientMetadataClaimNames.CLIENT_SECRET).toString()));
        assertEquals(List.of("refresh_token", "client_credentials", "authorization_code"), client.get(OidcClientMetadataClaimNames.GRANT_TYPES));
        assertEquals(List.of("http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint", "https://key-server.gxfs.dev/realms/gaia-x/broker/ssi-oidc/endpoint"), 
        		client.get(OidcClientMetadataClaimNames.REDIRECT_URIS));
        assertEquals("openid profile email", client.get(OidcClientMetadataClaimNames.SCOPE).toString());
    }

    @Test
    void registerClientTest() throws Exception {
    	List<RegisteredClient> clients = clientsRepo.getAllClients();
    	assertEquals(4, clients.size());
    	String json = "{\"application_type\": \"web\", \"client_name\": \"My Web App\", \"grant_types\": [\"authorization_code\", \"client_credentials\"], " + 
    			"\"redirect_uris\": [\"http://new.client.com/test\", \"https://new.client.org/endpoint\"], \"response_types\": [\"code\"], " + 
    			"\"scope\": \"openid profile email\", \"tsa_restrictions\": {\"limit\": 32, \"restriction\": \"constraint\", \"enabled\": true}, " + 
    			"\"ssi_auth_type\": \"OIDC\"}";
    	Jwt jwt = buildJwt("aas-app-oidc", "client.create");
        MvcResult result = mockMvc.perform(post("/connect/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json)
        		.with(jwt().jwt(jwt)))
                .andExpect(status().isCreated()).andReturn();
        Map<String, Object> client = mapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
        assertEquals("My Web App", client.get(OidcClientMetadataClaimNames.CLIENT_NAME));
        assertEquals(List.of("client_credentials", "authorization_code"), client.get(OidcClientMetadataClaimNames.GRANT_TYPES));
        assertEquals(List.of("https://new.client.org/endpoint", "http://new.client.com/test"), client.get(OidcClientMetadataClaimNames.REDIRECT_URIS));
        assertEquals(List.of("code"), client.get(OidcClientMetadataClaimNames.RESPONSE_TYPES));
        clients = clientsRepo.getAllClients();
        assertEquals(5, clients.size());
        String clientId = client.get(OidcClientMetadataClaimNames.CLIENT_ID).toString();
        String secret = client.get(OidcClientMetadataClaimNames.CLIENT_SECRET).toString();
    	RegisteredClient reClient = clientsRepo.findByClientId(clientId);
    	assertNotNull(reClient);
    	assertEquals(clientId, reClient.getClientId());
        assertEquals("My Web App", reClient.getClientName());
        assertEquals(Set.of("profile", "openid", "email"), reClient.getScopes());
        ClientSettings cls = reClient.getClientSettings();
        assertNotNull(cls);
        assertEquals("web", cls.getSetting("application_type"));
        assertEquals("OIDC", cls.getSetting(SsiClientCustomClaims.SSI_AUTH_TYPE));
        assertNotNull(cls.getSetting(SsiClientCustomClaims.TSA_RESTRICTIONS));
        Map<String, Object> restrictions = cls.getSetting(SsiClientCustomClaims.TSA_RESTRICTIONS);
        assertEquals(32, restrictions.get("limit"));
        assertEquals("constraint", restrictions.get("restriction"));
        assertTrue((Boolean) restrictions.get("enabled"));
        
        // now test auth with new client creds
        String bearer = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
        result = mockMvc.perform(post("/oauth2/token")
                .header("Authorization", "Basic " + bearer)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()))
            .andExpect(status().isOk())
            .andReturn();
        // how to test auth with access token?
    }
    
    private Jwt buildJwt(String clientId, String clientScope) {
    	RegisteredClient reClient = clientsRepo.findByClientId(clientId);
    	OAuth2Authorization auth = OAuth2Authorization.withRegisteredClient(reClient)
    			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
    			.principalName("test-user")
    			.token(new OAuth2AuthorizationCode("client-token", Instant.now(), Instant.now().plusSeconds(10)))
    			.token(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "client-token", Instant.now(), Instant.now().plusSeconds(10)), 
    					m -> m.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, Map.of(OidcClientMetadataClaimNames.SCOPE, List.of(clientScope))))
    			.build();
    	authService.save(auth);
    	return Jwt.withTokenValue("client-token") 
    			.header("alg", "none")
    			.claim("sub", "test-user")
    			.build();
    }
}



//java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
