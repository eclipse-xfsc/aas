package eu.xfsc.aas.client;

import java.net.HttpURLConnection;
import java.net.URL;

import org.springframework.beans.factory.annotation.Value;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RestInvitationServiceClientImpl implements InvitationServiceClient {

    @Value("${aas.invitation.uri}")
    private String inUri;

    @Override
    public String getMobileInvitationUrl(String uri) {
    	log.debug("getMobileInvitationUrl.enter; got uri: {}", uri);
    	String result = null;
        try {
	        URL url = new URL(uri);
	        HttpURLConnection con = (HttpURLConnection) url.openConnection();
	        con.setRequestMethod("GET");
	        con.setInstanceFollowRedirects(false);
	    
	        int status = con.getResponseCode();
	        if (status == HttpURLConnection.HTTP_MOVED_TEMP || status == HttpURLConnection.HTTP_MOVED_PERM) {
	            String location = con.getHeaderField("Location");
	            URL newUrl = new URL(location);
	            result = inUri + newUrl.getQuery();
	        }          
        } catch (Exception ex) {
        	log.error("getMobileInvitationUrl.error", ex);
        }
    	log.debug("getMobileInvitationUrl.exit; returning: {}", result);
        return result;
    }  
}
