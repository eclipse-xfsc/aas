package eu.xfsc.aas.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import eu.xfsc.aas.client.InvitationServiceClient;
import eu.xfsc.aas.client.LocalTrustServiceClientImpl;
import eu.xfsc.aas.client.RestInvitationServiceClientImpl;
import eu.xfsc.aas.client.RestTrustServiceClientImpl;
import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.properties.StatusProperties;

@Configuration
public class ClientsConfig {

    @Bean
    @Profile("prod")
    public TrustServiceClient restTrustServiceClient() {
        return new RestTrustServiceClientImpl();
    }

    @Bean
    @Profile("!prod")
    public TrustServiceClient localTrustServiceClient(StatusProperties statusProperties) {
        return new LocalTrustServiceClientImpl(statusProperties);
    }

    @Bean
    @Profile("prod")
    public InvitationServiceClient restInvitationServiceClient() {
        return new RestInvitationServiceClientImpl();
    }

    @Bean
    @Profile("!prod")
    public InvitationServiceClient localInvitationServiceClient(StatusProperties statusProperties) {
        return new InvitationServiceClient() {

			@Override
			public String getMobileInvitationUrl(String url) {
				return url;
			}
        	
        };
    }
    
}
