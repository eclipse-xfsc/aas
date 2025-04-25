package eu.xfsc.aas.controller;

import static eu.xfsc.aas.generated.model.AccessRequestStatusDto.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.xfsc.aas.client.IamClient;
import eu.xfsc.aas.client.LocalTrustServiceClientImpl;
import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.generated.model.AccessRequestDto;
import eu.xfsc.aas.generated.model.AccessResponseDto;
import eu.xfsc.aas.generated.model.ServiceAccessScopeDto;
import eu.xfsc.aas.model.TrustServicePolicy;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase.DatabaseProvider;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@AutoConfigureEmbeddedDatabase(provider = DatabaseProvider.ZONKY)
public class IatProvisionFlowTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Value("${aas.tsa.request.count}")
    private int loopCount = 2;

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TrustServiceClient trustServiceClient;

    @MockBean
    private IamClient iamClient;

    @Test
    public void testIatRequestFlow() throws Exception {

        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_IAT_PROOF_RESULT, ACCEPTED);

        String requestId = getIatRequestId();

        when(iamClient.registerIam(any(), any())).thenReturn(Map.of("registration_access_token", "keycloakIat"));
        
        AccessResponseDto result = getIatResult(requestId);
        assertEquals(requestId, result.getRequestId());
        assertEquals(ACCEPTED, result.getStatus());
        assertNotNull(result.getInitialAccessToken());
    }

    @Test
    public void testIatRequestReject() throws Exception {
        
        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_IAT_PROOF_RESULT, REJECTED);
        
        String requestId = getIatRequestId();
        AccessResponseDto result = getIatResult(requestId);
        assertEquals(requestId, result.getRequestId());
        assertEquals(REJECTED, result.getStatus());
        assertNull(result.getInitialAccessToken());
    }

    @Test
    public void testIatRequestTimeout() throws Exception {
        
        ((LocalTrustServiceClientImpl) trustServiceClient).setStatusConfig(TrustServicePolicy.GET_IAT_PROOF_RESULT, TIMED_OUT);
        
        String requestId = getIatRequestId();
        AccessResponseDto result = getIatResult(requestId);
        assertEquals(requestId, result.getRequestId());
        assertEquals(TIMED_OUT, result.getStatus());
        assertNull(result.getInitialAccessToken());
    }

    private String getIatRequestId() throws Exception {
        
        AccessRequestDto requestDto = new AccessRequestDto()
                .subject("did:sample:1234567890")
                .entity(new ServiceAccessScopeDto().scope("openid").did("did:sample:qwerty"));
        MvcResult result = mockMvc.perform(
                post("/clients/iat/requests")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isOk())
                .andReturn();
        String response = result.getResponse().getContentAsString();
        AccessResponseDto ard = objectMapper.readValue(response, AccessResponseDto.class);
        assertNull(ard.getInitialAccessToken());
        assertNotNull(ard.getRequestId());
        return ard.getRequestId();
    }
    
    private AccessResponseDto getIatResult(String requestId) throws Exception {

        int cnt = 0;
        AccessResponseDto ard;
        do {
            MvcResult result = mockMvc.perform(
                    get("/clients/iat/requests/" + requestId)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andReturn();
            String response = result.getResponse().getContentAsString();
            ard = objectMapper.readValue(response, AccessResponseDto.class);
            assertEquals(requestId, ard.getRequestId());
            cnt++;
        } while (cnt <= loopCount);
        return ard;
    }
}
