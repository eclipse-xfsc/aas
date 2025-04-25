package eu.xfsc.aas.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SsiCorsConfigurationSource implements CorsConfigurationSource {
	
	private SsiClientsRepository clientsRepo;
	private CorsConfigurationSource cache;
	
	public SsiCorsConfigurationSource(SsiClientsRepository clientsRepo) {
		this.clientsRepo = clientsRepo;
	}

	@Override
	public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
		if (cache == null) {
			// synchronize?
			cache = corsConfigurationSource();
		}
		return cache.getCorsConfiguration(request);
	}
	
	public void invalidate() {
		cache = null;
	}
	
    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // filling CORS origins from Client redirect-uris
        Set<String> uris = new HashSet<>();
        List<RegisteredClient> clients = clientsRepo.getAllClients();
        clients.stream().flatMap(cl -> cl.getRedirectUris().stream())
        	.forEach(u -> {
        		try {
        		    URI uri = new URI(u);
        		    uris.add(uri.getScheme() + "://" + uri.getHost());
        		} catch (URISyntaxException ex) {
        			// skip it?
        		}
        	});
        uris.add("https://fc-demo-server.gxfs.dev");
        uris.add("https://integration.gxfs.dev");
        uris.add("http://127.0.0.1:3000"); // i doubt port is required here
        config.setAllowedOrigins(new ArrayList<>(uris));
        log.debug("corsConfigurationSource; CORS origins: {}", config.getAllowedOrigins());
        
        config.addAllowedHeader("*");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("GET");
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/.well-known/**", config);
        source.registerCorsConfiguration("/connect/**", config);        
        source.registerCorsConfiguration("/logout", config);
        source.registerCorsConfiguration("/oauth2/**", config);
        //source.registerCorsConfiguration("/ssi/logout", config);
        return source;
    }	

}
