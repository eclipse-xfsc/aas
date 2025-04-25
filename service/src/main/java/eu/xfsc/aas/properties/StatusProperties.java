package eu.xfsc.aas.properties;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import eu.xfsc.aas.generated.model.AccessRequestStatusDto;
import lombok.Data;

@Data
@Component
@ConfigurationProperties(prefix = "aas.tsa")
public class StatusProperties {

    private Map<String, AccessRequestStatusDto> statuses;
    
    public AccessRequestStatusDto getPolicyStatus(String policy) {
        return statuses.get(policy);
    }
    
    public void setPolicyStatus(String policy, AccessRequestStatusDto status) {
        statuses.put(policy, status);
    }

}
