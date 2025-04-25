package eu.xfsc.aas.client;

import java.util.Map;

public interface TrustServiceClient {
    
    String PN_LINK = "link";
    String PN_NAMESPACE = "namespace";
    String PN_REQUEST_ID = "requestId";
    String PN_STATUS = "status";
    
    String LINK_SCHEME = "https://gaia-x.org/";
    
    String NS_LOGIN = "Login";
    String NS_ACCESS = "Access";
    
    Map<String, Object> evaluate(String policy, Map<String, Object> params);

}
