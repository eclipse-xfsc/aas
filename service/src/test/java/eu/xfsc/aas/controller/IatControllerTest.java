package eu.xfsc.aas.controller;

import com.fasterxml.jackson.databind.ObjectMapper;

import eu.xfsc.aas.client.IamClient;
import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.generated.model.AccessRequestDto;
import eu.xfsc.aas.generated.model.AccessRequestStatusDto;
import eu.xfsc.aas.generated.model.AccessResponseDto;
import eu.xfsc.aas.generated.model.ServiceAccessScopeDto;
import eu.xfsc.aas.model.TrustServicePolicy;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase.DatabaseProvider;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@AutoConfigureEmbeddedDatabase(provider = DatabaseProvider.ZONKY)
public class IatControllerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;
    @MockBean
    private TrustServiceClient trustServiceClient;
    @MockBean
    private IamClient iamClient;

    @Test
    void getRequest_missingRequestId_404() throws Exception {
        mockMvc.perform(
                        get("/clients/iat/request/"))
                .andExpect(status().isNotFound());
    }

    @Test
    void getRequest_correctRequest_pending_200() throws Exception {
        Map<String, Object> serviceResponse = Map.of(
                "iss", "responseSubject",
                "sub", "responseDid",
                "scope", "responseScope",
                "requestId", "responseRequestId",
                "status", AccessRequestStatusDto.PENDING);
        when(trustServiceClient.evaluate(eq(TrustServicePolicy.GET_IAT_PROOF_RESULT), any())).thenReturn(serviceResponse);

        mockMvc.perform(
                        get("/clients/iat/requests/testRequestId")
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());
    }

    @Test
    void getRequest_correctRequest_accepted_200() throws Exception {
        Map<String, Object> serviceResponse = Map.of(
                "iss", "responseSubject",
                "sub", "responseDid",
                "scope", "responseScope",
                "requestId", "responseRequestId",
                "status", AccessRequestStatusDto.ACCEPTED);
        when(trustServiceClient.evaluate(eq(TrustServicePolicy.GET_IAT_PROOF_RESULT), any())).thenReturn(serviceResponse);
        when(iamClient.registerIam(any(), any())).thenReturn(Map.of("registration_access_token", "keycloakIat"));

        mockMvc.perform(
                        get("/clients/iat/requests/testRequestId")
                                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound());
    }

    @Test
    void postRequest_missingAccessRequest_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto())))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_missingServiceAccessScope_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto().subject("testSubject"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_missingSubject_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto()
                                        .entity(
                                                new ServiceAccessScopeDto().scope("testScope").did("testDid")
                                        )
                                )))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_missingSubjectDid_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto()
                                        .subject("testSubject")
                                        .entity(
                                                new ServiceAccessScopeDto().scope("testScope")
                                        )
                                )))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_missingSubjectScope_400() throws Exception {
        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new AccessRequestDto()
                                        .subject("testSubject")
                                        .entity(
                                                new ServiceAccessScopeDto().did("testDid")
                                        )
                                )))
                .andExpect(status().isBadRequest());
    }

    @Test
    void postRequest_correctRequest_200() throws Exception {
        AccessRequestDto requestDto = new AccessRequestDto()
                .subject("testSubject")
                .entity(new ServiceAccessScopeDto().scope("profile testScope").did("testDid"));
        Map<String, Object> serviceResponse = Map.of("requestId", "responseRequestId");
        AccessResponseDto expectedResponse = new AccessResponseDto()
                .requestId("responseRequestId")
                .subject("testSubject")
                .entity(new ServiceAccessScopeDto().scope("profile testScope").did("testDid"));

        when(trustServiceClient.evaluate(eq(TrustServicePolicy.GET_IAT_PROOF_INVITATION), any())).thenReturn(serviceResponse);

        mockMvc.perform(
                        post("/clients/iat/requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(requestDto)))
                .andExpect(status().isOk())
                .andExpect(content().json(objectMapper.writeValueAsString(expectedResponse), false));
    }

}
