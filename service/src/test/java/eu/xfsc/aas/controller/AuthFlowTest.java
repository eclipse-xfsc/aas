package eu.xfsc.aas.controller;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.ChecksumException;
import com.google.zxing.FormatException;
import com.google.zxing.NotFoundException;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import eu.xfsc.aas.client.TrustServiceClient;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase;
import io.zonky.test.db.AutoConfigureEmbeddedDatabase.DatabaseProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@AutoConfigureEmbeddedDatabase(provider = DatabaseProvider.ZONKY)
public abstract class AuthFlowTest {

    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<Map<String, Object>>() {
    };
    
    protected static String challenge = UUID.randomUUID().toString(); 
    
    @Value("${aas.iam.base-uri}")
    protected String keycloakUri;
    @Value("${aas.oidc.issuer}")
    protected String oidcIssuer;
    @Value("${aas.tsa.request.count}")
    private int tryCount;
	
    @Autowired
    protected MockMvc mockMvc;
    @Autowired
    protected ObjectMapper mapper;
    @Autowired
    protected TrustServiceClient trustServiceClient;
	
    
    protected String statusCallback(HttpSession ssn, int finalStatus) {
    	String redirect = null;
    	try {
    		int cnt = 0;
    		do {
    			MvcResult stsResult = mockMvc.perform(get("/ssi/login/status")
    					.contentType(MediaType.APPLICATION_JSON)
    					.cookie(new Cookie("JSESSIONID", ssn.getId())).session((MockHttpSession) ssn))
    				.andReturn();
				cnt++;
				if (cnt <= tryCount) {
					assertEquals(HttpStatus.ACCEPTED.value(), stsResult.getResponse().getStatus());
				} else {
					assertEquals(finalStatus, stsResult.getResponse().getStatus());
					if (finalStatus == 302) {
						redirect = stsResult.getResponse().getRedirectedUrl();
					}
					break;
				}
    		} while (true);
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return redirect;
    }

    
    protected Map<String, Object> getAuthClaims(String scope, String state, String responseType, String clientId, String redirectUri, String nonce,  
            String secret, ClientAuthenticationMethod authMethod, Map<String, Object> optional, Function<String, String> urlBuilder, Function<HttpSession, 
            String> callback) throws Exception {

        String authCode = getAuthCode(scope, state, responseType, clientId, redirectUri, nonce, optional, urlBuilder, callback);
        MvcResult result;
        if (authMethod == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
            result = mockMvc.perform(
                    post("/oauth2/token")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param(OAuth2ParameterNames.CODE, authCode)
                            .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                            .param(OAuth2ParameterNames.REDIRECT_URI, redirectUri)
                            .param(OAuth2ParameterNames.CLIENT_ID, clientId)
                            .param(OAuth2ParameterNames.CLIENT_SECRET, secret))
                    .andExpect(status().isOk())
                    .andReturn();
        } else if (authMethod == ClientAuthenticationMethod.NONE) { // || secret == null) {
          result = mockMvc.perform(
                post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param(OAuth2ParameterNames.CODE, authCode)
                        .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                        .param(OAuth2ParameterNames.REDIRECT_URI, redirectUri)
                        .param(OAuth2ParameterNames.CLIENT_ID, clientId)
                        .param("code_verifier", challenge))
                .andExpect(status().isOk())
                .andReturn();
        } else {
          // ClientAuthenticationMethod.CLIENT_SECRET_BASIC
          String bearer = Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes());
          result = mockMvc.perform(
                post("/oauth2/token")
                        .header("Authorization", "Basic " + bearer)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param(OAuth2ParameterNames.CODE, authCode)
                        .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                        .param(OAuth2ParameterNames.REDIRECT_URI, redirectUri))
                .andExpect(status().isOk())
                .andReturn();
        }
        
        String token = result.getResponse().getContentAsString();
        Map<String, Object> tokenFields = new JacksonJsonParser().parseMap(token);
        
        assertNotNull(tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN));
        assertNotNull(tokenFields.get(OidcParameterNames.ID_TOKEN));
        assertNotNull(tokenFields.get(OAuth2ParameterNames.EXPIRES_IN));
        assertNotNull(tokenFields.get(OAuth2ParameterNames.TOKEN_TYPE));
        assertTrue(((Integer) tokenFields.get(OAuth2ParameterNames.EXPIRES_IN)) > 250); // default is 300, we set it to 600
        assertEquals("Bearer", tokenFields.get(OAuth2ParameterNames.TOKEN_TYPE));
        // check session.getMaxInactiveInterval() too?
        
        String accessToken = tokenFields.get(OAuth2ParameterNames.ACCESS_TOKEN).toString();
        String refreshToken = (String) tokenFields.get(OAuth2ParameterNames.REFRESH_TOKEN);  // can be null
        JWT jwt = JWTParser.parse(accessToken);
        Object o = jwt.getJWTClaimsSet().getClaim(IdTokenClaimNames.AUTH_TIME);
        assertNull(o);
        
        String idToken = tokenFields.get(OidcParameterNames.ID_TOKEN).toString();
        jwt = JWTParser.parse(idToken);
        Map<String, Object> claims = new HashMap<>(jwt.getJWTClaimsSet().getClaims());
        claims.put(OAuth2ParameterNames.ACCESS_TOKEN, accessToken);
        claims.put(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        return claims;
    }
    
    private String getAuthCode(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, 
            Map<String, Object> optional, Function<String, String> urlBuilder, Function<HttpSession, String> callback) throws Exception {

        MvcResult authResult = getAuthResult(scope, state, responseType, clientId, redirectUri, nonce, optional, urlBuilder, callback, "/oauth2/authorize");
        HttpSession session = authResult.getRequest().getSession(false);

        Map<String, Object> params = getAuthRequestParams(scope, state, responseType, clientId, redirectUri, nonce, optional);
        String rq = getAuthRequest(params);
        Object[] values = params.values().toArray(new Object[params.size()]);
        
        authResult = mockMvc
                .perform(get("/oauth2/authorize?" + rq, values)
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(redirectUri))) 
                .andReturn();

        String reUrl = authResult.getResponse().getRedirectedUrl();
        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(reUrl).build().getQueryParams();
        return queryParams.getFirst(OAuth2ParameterNames.CODE); // responseType);
    }

    protected MvcResult getAuthResult(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, 
            Map<String, Object> optional, Function<String, String> urlBuilder, Function<HttpSession, String> callback, String loginRedirect) throws Exception {

        Map<String, Object> params = getAuthRequestParams(scope, state, responseType, clientId, redirectUri, nonce, optional);
        String rq = getAuthRequest(params);
        Object[] values = params.values().toArray(new Object[params.size()]);

        MvcResult result = mockMvc
                .perform(get("/oauth2/authorize?" + rq, values).accept(MediaType.TEXT_HTML,
                        MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("/ssi/login"))).andReturn(); 

        HttpSession session = result.getRequest().getSession(false);

        result = mockMvc
                .perform(get("/ssi/login") 
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();
        
        assertNotNull(result.getModelAndView().getModel().get("qrUrl"));
        assertNotNull(result.getModelAndView().getModel().get("requestId"));
        assertNotNull(result.getModelAndView().getModel().get("scope"));

        session = result.getRequest().getSession(false);
        String qrUrl = result.getModelAndView().getModel().get("qrUrl").toString();
        String requestId = result.getModelAndView().getModel().get("requestId").toString();
        //String requestId = "123";

        result = mockMvc
                .perform(get(qrUrl).accept(MediaType.IMAGE_PNG, MediaType.IMAGE_GIF)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session))
                .andExpect(status().isOk()).andReturn();

        String expectedUrl = urlBuilder.apply(requestId); 
        String resultQrUrl = decodeQR(result.getResponse().getContentAsByteArray());
        assertEquals(expectedUrl, resultQrUrl);

        String redirectUrl = null;
        if (callback != null) {
            redirectUrl = callback.apply(session);
        }
        
        if (redirectUrl == null) {
        	result = mockMvc
                .perform(post("/login")
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session)
                        .param(OAuth2ParameterNames.USERNAME, requestId).param(OAuth2ParameterNames.PASSWORD, clientId))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString(loginRedirect))) //!!
                .andReturn();
        } else {
        	assertEquals(loginRedirect, redirectUrl);
        	result = mockMvc
                .perform(get(redirectUrl)
                        .accept(MediaType.TEXT_HTML, MediaType.APPLICATION_XHTML_XML, MediaType.APPLICATION_XML)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .cookie(new Cookie("JSESSIONID", session.getId())).session((MockHttpSession) session)
                        .param(OAuth2ParameterNames.USERNAME, requestId).param(OAuth2ParameterNames.PASSWORD, clientId))
                .andExpect(status().isOk()) 
                .andReturn();        	
        }
        return result;
    }
    
    protected Map<String, Object> getUserInfo(String accessToken) throws Exception {
        MvcResult result = mockMvc.perform(
                get("/userinfo")
                    .header("Authorization", "Bearer " + accessToken)
                    .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();
        return mapper.readValue(result.getResponse().getContentAsString(), MAP_TYPE_REF);
    }
    
    protected Map<String, Object> getAuthRequestParams(String scope, String state, String responseType, String clientId, String redirectUri, String nonce, 
            Map<String, Object> optional) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put(OAuth2ParameterNames.SCOPE, scope);
        if (state != null) {
            params.put(OAuth2ParameterNames.STATE, state);
        }
        params.put(OAuth2ParameterNames.RESPONSE_TYPE, responseType);
        params.put(OAuth2ParameterNames.CLIENT_ID, clientId);
        params.put(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
        if (nonce != null) {
            params.put(OidcParameterNames.NONCE, nonce);
        }
        if (optional != null) {
            params.putAll(optional);
        }
        return params;
    }	

    protected String getAuthRequest(Map<String, Object> params) {
        return params.keySet().stream().map(k -> k + "={" + k + "}").collect(Collectors.joining("&"));
    }
    
    private String decodeQR(byte[] content) throws IOException, ChecksumException, NotFoundException, FormatException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(content));
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(image)));
        return new QRCodeReader().decode(bitmap).getText();
    }
    
    protected String getMessage(String code, Locale locale) {
        ResourceBundle resourceBundle = ResourceBundle.getBundle("language/messages", locale);
        try {
            return resourceBundle.getString(code);
        } catch (Exception ex) {
            return code;
        }
    }

    
}
