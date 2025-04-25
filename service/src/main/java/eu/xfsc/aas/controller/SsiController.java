package eu.xfsc.aas.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import eu.xfsc.aas.client.TrustServiceClient;
import eu.xfsc.aas.generated.model.AccessRequestStatusDto;
import eu.xfsc.aas.model.SsiAuthErrorCodes;
import eu.xfsc.aas.model.SsiClientCustomClaims;
import eu.xfsc.aas.service.SsiBrokerService;
import eu.xfsc.aas.service.SsiClientsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/ssi")
public class SsiController {

    private final SsiBrokerService ssiBrokerService;

    @GetMapping(value = "/login")
    public String login(HttpServletRequest request, Model model) {
        DefaultSavedRequest auth = (DefaultSavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        Locale locale = getLocale(request); 
        
        if (auth == null) {
            String out = request.getParameter("logout");
            if (out == null) {
                model.addAttribute("errorMessage", getErrorMessage("sessionTimeout", locale));
            } else {
            	log.debug("login; no saved request found, model: {}", model.asMap());
                // assume OIDC client for now..
                // but which clientId put to the model? hen we could use its scope..
                model.addAttribute(OAuth2ParameterNames.SCOPE, new String[] {OidcScopes.OPENID});
                request.getSession().setAttribute("requestId", ssiBrokerService.oidcAuthorize(model.asMap()));
            }
            return "login-template.html";
        }
        
        model.addAttribute(OAuth2ParameterNames.SCOPE, auth.getParameterValues(OAuth2ParameterNames.SCOPE));
        String error = request.getParameter(OAuth2ParameterNames.ERROR);
        if (error != null) {
            model.addAttribute("errorMessage", getErrorMessage(error, locale));
        }

        String[] clientId = auth.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
        if (clientId != null && clientId.length > 0) {
        	RegisteredClient client = ssiBrokerService.getClientsRepository().findByClientId(clientId[0]);
        	if (client != null) {
                model.addAttribute("clientId", client.getClientId());
        		String ssiAuthType = client.getClientSettings().getSetting(SsiClientCustomClaims.SSI_AUTH_TYPE);
        		if (SsiClientCustomClaims.AUTH_TYPE_SIOP.equalsIgnoreCase(ssiAuthType)) {
	                request.getSession().setAttribute("requestId", ssiBrokerService.siopAuthorize(model.asMap()));
	            } else {
	                String[] age = auth.getParameterValues("max_age");
	                if (age != null && age.length > 0) {
	                    model.addAttribute("max_age", age[0]);
	                }
	    
	                String[] hint = auth.getParameterValues("id_token_hint");
	                if (hint != null && hint.length > 0) {
	                    String sub = getSubject(hint[0]);
	                    if (sub != null) {
	                        model.addAttribute(IdTokenClaimNames.SUB, sub);
	                    }
	                }
	 
	               request.getSession().setAttribute("requestId", ssiBrokerService.oidcAuthorize(model.asMap()));
	            }
	            return "login-template.html";
        	}
        }

        throw new OAuth2AuthenticationException("unknown client: " + (clientId == null ? null : Arrays.toString(clientId)));
    }
    
    @GetMapping(value = "/login/status")
    public ResponseEntity<Void> loginStatus(HttpServletRequest request, HttpServletResponse response) { //, Model model) {    
        String requestId = (String) request.getSession().getAttribute("requestId");
        if (requestId == null) {
        	return ResponseEntity.badRequest().build(); 
        }

        Map<String, Object> claims = ssiBrokerService.getUserClaims(requestId, true);
        AccessRequestStatusDto sts = (AccessRequestStatusDto) claims.get(TrustServiceClient.PN_STATUS);
        try {
	        switch (sts) {
	            case ACCEPTED:
	                return ResponseEntity.status(HttpStatus.FOUND).build();
	            case REJECTED:
	                response.sendRedirect("/ssi/login?error=" + SsiAuthErrorCodes.LOGIN_REJECTED);
	                return ResponseEntity.status(HttpStatus.BAD_GATEWAY).build(); 
	            case TIMED_OUT:
	                response.sendRedirect("/ssi/login?error=" + SsiAuthErrorCodes.LOGIN_TIMED_OUT);
	                return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).build();
	            default:    
	            	return ResponseEntity.accepted().build();
	        }
        } catch (IOException ex) {
        	ex.printStackTrace();
        	return ResponseEntity.internalServerError().build(); 
        }
    }

  /* @GetMapping(value = "/logout")
    public ResponseEntity logout(HttpServletRequest request) throws ServletException
    {   
        var auth =  SecurityContextHolder.getContext().getAuthentication();
        if( auth != null ) {
            String requestId = auth.getName();
            log.debug("Request ID %s", requestId);
            if (request != null)  {
                log.debug("Clean Cache for User:" + requestId);
                ssiBrokerService.ClearById(requestId);
            }
             
            request.logout();
            return new ResponseEntity<>(HttpStatus.OK); 
        } else 
           return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }*/

    private String getErrorMessage(String errorCode, Locale locale) {
        ResourceBundle resourceBundle = ResourceBundle.getBundle("language/messages", locale);
        try {
            return resourceBundle.getString(errorCode);
        } catch (Exception ex) {
            log.warn("getErrorMessage.error; no resource found for error: {}", errorCode);
        }
        return errorCode;
    }
    
    private Locale getLocale(HttpServletRequest request) {
        Locale locale; 
        String lang = request.getParameter("lang");
        if (lang == null) {
            locale = (Locale) request.getSession().getAttribute("session.current.locale");
            if (locale == null) {
                locale = request.getLocale();
            }
        } else {
            locale = Locale.forLanguageTag(lang);
        }
    	return locale;
    }

    private String getSubject(String idToken) {
        try {
            JWT jwt = JWTParser.parse(idToken);
            return jwt.getJWTClaimsSet().getSubject();
        } catch (Exception ex) {
            log.debug("getSubject; cannot parse JWT: {}", idToken);
            // better have it in local var. but don't know is it thread-safe or not..
            JacksonJsonParser jsonParser = new JacksonJsonParser();
            Map<String, Object> params = jsonParser.parseMap(idToken);
            return (String) params.get(IdTokenClaimNames.SUB);
        }
    }

    @GetMapping(value = "/qr/{qrid}", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> getQR(@PathVariable String qrid) {
        return ResponseEntity.ok(ssiBrokerService.getQR(qrid));
    }
    
    @ResponseBody
    @PostMapping(value = "/siop-callback", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public void siopCallback(@RequestParam MultiValueMap<String, Object> body) {

        String error;
        Map<String, Object> claims;
        String idToken = (String) body.getFirst(OidcParameterNames.ID_TOKEN);
        if (idToken == null) {
            error = (String) body.getFirst(OAuth2ParameterNames.ERROR);
            String desc = (String) body.getFirst(OAuth2ParameterNames.ERROR_DESCRIPTION);
            if (error != null || desc != null) {
                claims = new HashMap<>();
                claims.put(OAuth2ParameterNames.ERROR, String.join(": ", error, desc));
                String nonce = (String) body.getFirst(OidcParameterNames.NONCE);
                if (nonce == null) {
                    nonce = (String) body.getFirst(OAuth2ParameterNames.STATE);
                }
                claims.put(OidcParameterNames.NONCE, nonce);
            } else {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid_response: no id_token nor error provided"); 
            }
        } else {

            try {
                JWT jwt = JWTParser.parse(idToken);
                claims = jwt.getJWTClaimsSet().getClaims();
            } catch (ParseException ex) {
                // log it?
                JacksonJsonParser parser = new JacksonJsonParser();
                claims = parser.parseMap(idToken);
            }
        }
        
        ssiBrokerService.processSiopLoginResponse(claims);
    }
    
}
 