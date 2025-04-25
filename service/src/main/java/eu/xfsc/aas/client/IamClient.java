package eu.xfsc.aas.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class IamClient {

    private final WebClient client;
    private static final ParameterizedTypeReference<Map<String, Object>> MAP_TYPE_REF = new ParameterizedTypeReference<>() {
    };

    @Value("${aas.iam.iat.dcr-uri}")
    private String clientRegistrationUri;

    @Value("${aas.iam.iat.secret}")
    private String clientIat;

    public IamClient() {
        client = WebClient.builder()
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    public Map<String, Object> registerIam(String clientName, List<String> redirectUris) {
        log.debug("registerIam.enter; got clientName: {}, redirectUris: {}", clientName, redirectUris);

        Map<String, Object> map = new HashMap<>();
        map.put("client_name", clientName);
        map.put("redirect_uris", redirectUris);
        map.put("grant_types", List.of("authorization_code"));

        Flux<Map<String, Object>> trustServiceResponse = client.post()
                .uri(clientRegistrationUri)
                .headers(h -> h.setBearerAuth(clientIat))
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(map)
                .retrieve()
                .bodyToFlux(MAP_TYPE_REF);

        Map<String, Object> result = trustServiceResponse.blockFirst();
        log.debug("registerIam.exit; returning: {}", result.size());
        return result;
    }
}
