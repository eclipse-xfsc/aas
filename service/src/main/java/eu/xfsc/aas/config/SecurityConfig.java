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

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import eu.xfsc.aas.service.SsiAuthProvider;
import eu.xfsc.aas.service.SsiJwtCustomizer;
import lombok.extern.slf4j.Slf4j;

/**
 * The Spring Security config.
 */
@Slf4j
@EnableWebSecurity//(debug = true)
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {
    	log.debug("defaultSecurityFilterChain.enter");
    	HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setRequestMatcher(new OrRequestMatcher(antMatcher("/oauth2/**"), antMatcher("/connect/**")));
        requestCache.setMatchingRequestParameterName(null);
    	http
    		.csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())
        	.authorizeHttpRequests(authorize -> authorize 
        			.requestMatchers(antMatcher("/api/**")).permitAll()
        			.requestMatchers(antMatcher("/swagger-ui/**")).permitAll()
        			.requestMatchers(antMatcher("/login")).permitAll()
        			.requestMatchers(antMatcher("/error")).permitAll()
        			.requestMatchers(antMatcher("/actuator")).permitAll()
        			.requestMatchers(antMatcher("/actuator/**")).permitAll()
        			.requestMatchers(antMatcher("/**/*.{js,html,css}")).permitAll()
        			.requestMatchers(antMatcher("/.well-known/**")).permitAll()
        			.requestMatchers(antMatcher("/cip/**")).permitAll()
        			.requestMatchers(antMatcher("/clients/**")).permitAll()
        			//.requestMatchers(antMatcher("/connect/**")).permitAll()
        			.requestMatchers(antMatcher("/ssi/**")).permitAll()
        			.requestMatchers(antMatcher(HttpMethod.OPTIONS, "/oauth2/token")).permitAll()
        			.anyRequest().authenticated()
        		)
        	.formLogin(login -> login.failureHandler(ssiAuthenticationFailureHandler()))
            .logout(logout -> logout
            		.logoutSuccessUrl("/ssi/login?logout")
            		.invalidateHttpSession(true))
           	.requestCache(cache -> cache.requestCache(requestCache));
    	log.debug("defaultSecurityFilterChain.exit");
        return http.build();
    }

    @Bean
    public AuthenticationProvider authProvider() {
        return new SsiAuthProvider();
    }

    @Bean 
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return new SsiJwtCustomizer();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
    	// returns bcrypt encoder
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }    

    private AuthenticationFailureHandler ssiAuthenticationFailureHandler() {
        return (request, response, exception) -> {
            String error = exception.getMessage();
            if (error == null && exception instanceof OAuth2AuthenticationException) {
                error = ((OAuth2AuthenticationException) exception).getError().getErrorCode();
            }
            String redirectUrl = "/ssi/login?error=" + error;
            response.sendRedirect(redirectUrl);
        };
    }
}
