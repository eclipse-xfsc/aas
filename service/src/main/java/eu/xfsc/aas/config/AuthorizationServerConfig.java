/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.xfsc.aas.config;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import eu.xfsc.aas.properties.ScopeProperties;
import eu.xfsc.aas.service.SsiAuthorizationService;
import eu.xfsc.aas.service.SsiBrokerService;
import eu.xfsc.aas.service.SsiClientRegistrationAuthProvider;
import eu.xfsc.aas.service.SsiClientsRepository;
import eu.xfsc.aas.service.SsiCorsConfigurationSource;
import eu.xfsc.aas.service.SsiUserInfoAuthProvider;
import lombok.extern.slf4j.Slf4j;

/**
 * The Spring Authorization Server config.
 */
@Slf4j
@Configuration
public class AuthorizationServerConfig {

    @Value("${aas.cache.size}")
    private int cacheSize;
    @Value("${aas.cache.ttl}")
    private Duration cacheTtl;
    @Value("${aas.oidc.issuer}")
    private String oidcIssuer;
    @Value("${aas.jwk.length}")
    private int jwkLength;
    @Value("${aas.jwk.secret}")
    private String jwkSecret;
    
    private final ScopeProperties scopeProperties;
    
    @Autowired
    public AuthorizationServerConfig(ScopeProperties scopeProperties) {
        this.scopeProperties = scopeProperties;
    }
    
	@Bean 
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, SsiClientsRepository clientsRepo, SsiBrokerService ssiBroker) throws Exception {
    	log.debug("authorizationServerSecurityFilterChain.enter");
    	SsiCorsConfigurationSource corsSource = new SsiCorsConfigurationSource(clientsRepo);
		applyOidcSettings(http, corsSource, ssiBroker);
		
		http  
		    .cors(cors -> cors.configurationSource(corsSource))
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/ssi/login")))
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

    	log.debug("authorizationServerSecurityFilterChain.exit");
		return http.build();
	}   
	
    private void applyOidcSettings(HttpSecurity http, SsiCorsConfigurationSource corsSource, SsiBrokerService ssiBroker) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

   		//authorizationServerConfigurer.authorizationEndpoint(authorizationEndpoint -> 
   		//	authorizationEndpoint.authenticationProvider(new SsiAuthProvider(ssiBroker))
   		//);

   		authorizationServerConfigurer.authorizationServerMetadataEndpoint(authorizationServerMetadataEndpoint -> 
   			authorizationServerMetadataEndpoint.authorizationServerMetadataCustomizer(meta -> meta
   				.claims(claims())
   				.clientRegistrationEndpoint(oidcIssuer + "/connect/register")
   				.scopes(s -> {
					s.clear();
					s.addAll(scopeProperties.getScopes().keySet());
				})
   				.tokenEndpointAuthenticationMethods(m -> m.add(ClientAuthenticationMethod.NONE.getValue()))
   				.tokenIntrospectionEndpointAuthenticationMethods(m -> m.add(ClientAuthenticationMethod.NONE.getValue()))
   				.tokenRevocationEndpointAuthenticationMethods(m -> m.add(ClientAuthenticationMethod.NONE.getValue()))));
        
   		authorizationServerConfigurer.oidc(oidc -> 
			oidc.clientRegistrationEndpoint(clientRegistrationEndpoint -> 
				clientRegistrationEndpoint.authenticationProviders(providers -> {
					AuthenticationProvider proOne = providers.get(0);
					SsiClientRegistrationAuthProvider proSsi = new SsiClientRegistrationAuthProvider(corsSource, proOne);
					providers.set(0, proSsi);
				})
			)	
   		);

   		//authorizationServerConfigurer.oidc(oidc -> 
   		//	oidc.logoutEndpoint(logout -> logout.
		//);
		   		
   		authorizationServerConfigurer.oidc(oidc -> 
   			oidc.providerConfigurationEndpoint(providerConfigurationEndpoint ->
   				providerConfigurationEndpoint.providerConfigurationCustomizer(c ->
					c.claims(claims())
					.endSessionEndpoint(oidcIssuer + "/logout")
					.idTokenSigningAlgorithms(t -> t.add("ES256"))
					.scopes(s -> {
						s.clear();
						s.addAll(scopeProperties.getScopes().keySet());
					})
					.tokenEndpointAuthenticationMethods(m -> m.add(ClientAuthenticationMethod.NONE.getValue()))
					.tokenIntrospectionEndpointAuthenticationMethods(m -> m.add(ClientAuthenticationMethod.NONE.getValue()))
					.tokenRevocationEndpointAuthenticationMethods(m -> m.add(ClientAuthenticationMethod.NONE.getValue()))
				)
   			)
   		);
        
   		authorizationServerConfigurer.oidc(oidc ->
   			oidc.userInfoEndpoint(userInfoEndpoint ->
			    userInfoEndpoint.authenticationProvider(new SsiUserInfoAuthProvider(ssiBroker)) 
			    // .userInfoMapper(ctx -> userInfo(ctx))
			)
   		);
   		
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
		
        http.securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .addFilterAfter(new SsiOAuth2ValidationFilter(), LogoutFilter.class)
                .apply(authorizationServerConfigurer);
    }
    
    private Consumer<Map<String, Object>> claims() {
        List<String> supportedClaims = scopeProperties.getScopes()
                .values().stream().flatMap(List::stream)
                .distinct().sorted()
                .collect(Collectors.toList());

        return (claims) -> {
            claims.put("userinfo_signing_alg_values_supported", List.of("RS256", "ES256"));
            claims.put("display_values_supported", List.of("page"));
            claims.put("claims_supported", supportedClaims);
            claims.put("claims_locales_supported", List.of("en"));
            claims.put("ui_locales_supported", List.of("en", "de", "fr", "ru", "sk"));
        };
    }
        
    private OidcUserInfo userInfo(OidcUserInfoAuthenticationContext context) {
    	log.debug("userInfo.enter; got context: {}", context);
        OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
        JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
    	OidcUserInfo info = new OidcUserInfo(principal.getToken().getClaims());
    	log.debug("userInfo.exit; returning: {}", info);
    	return info;
    }

    @Bean
    public SsiClientsRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
    	return new SsiClientsRepository(jdbcTemplate);
    }

    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(oidcIssuer)
                .build();
    }
    
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        ECKey ecKey = generateEc();
        OctetSequenceKey hsKey = generateHs();
        JWKSet jwkSet = new JWKSet(List.of(rsaKey, ecKey, hsKey));
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private RSAKey generateRsa() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(jwkLength);
	        KeyPair keyPair = keyPairGenerator.generateKeyPair();
	        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
	        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
	        return new RSAKey.Builder(publicKey)
	                .privateKey(privateKey)
	                .keyUse(KeyUse.SIGNATURE)
	                .keyID(jwkSecret)
	                .build();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private ECKey generateEc() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            //keyPairGenerator.initialize(Curve.P_256.toECParameterSpec());
	        KeyPair keyPair = keyPairGenerator.generateKeyPair();
	        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
	        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
	    	Curve curve = Curve.forECParameterSpec(publicKey.getParams());
	        //return new ECKey.Builder(Curve.P_256, publicKey)
	    	return new ECKey.Builder(curve, publicKey)
	                .privateKey(privateKey)
	    			.keyID(UUID.randomUUID().toString())
	                .keyUse(KeyUse.SIGNATURE)
	                .build();
        } catch (NoSuchAlgorithmException e) { // | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }
    
    private OctetSequenceKey generateHs() {
        try {
        	SecretKey hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
        	return new OctetSequenceKey.Builder(hmacKey)
        			.keyID(UUID.randomUUID().toString())
        			.algorithm(JWSAlgorithm.HS256)
        			.build();    
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new SsiAuthorizationService(cacheSize, cacheTtl);
    }
    
    //@Bean
    //public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
    //    return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    //}
        
}

