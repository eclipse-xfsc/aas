package eu.xfsc.aas.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "aas")
public class ScopeProperties {

    private Map<String, List<String>> scopes;

}
