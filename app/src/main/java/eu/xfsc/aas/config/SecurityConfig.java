package eu.xfsc.aas.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@EnableWebSecurity //(debug=true)
public class SecurityConfig { 
    
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        
        http
          .authorizeHttpRequests()
          .requestMatchers("/demo").authenticated()
          .requestMatchers("/demo/read").hasAuthority("SCOPE_profile")
          .requestMatchers("/demo/write").hasAuthority("SCOPE_email")
          .anyRequest().permitAll()
          .and()
          .oauth2Login(oauth2Login ->
              oauth2Login
                  .loginPage("/oauth2/authorization/demo-app-oidc")
                  .authorizationEndpoint()
                  .authorizationRequestResolver(authorizationRequestResolver())
              )
          .oauth2Client(Customizer.withDefaults())
          .exceptionHandling()
          .accessDeniedHandler(accessDeniedHandler())
          .and()
          .logout()
          .logoutUrl("/logout")
          //Allows specifying the names of cookies to be removed on logout success.
          .deleteCookies("JSESSIONID")
          //Configures SecurityContextLogoutHandler to invalidate the HttpSession at the time of logout.
          //.invalidateHttpSession(true)
          .clearAuthentication(true)
          ;
        return http.build();
    }
    
    @Bean
    public CustomAuthorizationRequestResolver authorizationRequestResolver() {
        return new CustomAuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization/demo-app-oidc");
    }
    
    //@Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) -> {
            response.sendRedirect("/logout?redirect_url=" + request.getRequestURL()); 
        };
    }
}