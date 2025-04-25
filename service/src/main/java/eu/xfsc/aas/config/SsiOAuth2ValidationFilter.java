package eu.xfsc.aas.config;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

public class SsiOAuth2ValidationFilter extends OncePerRequestFilter {
    
    private static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";
    private static final Logger log = LoggerFactory.getLogger(SsiOAuth2ValidationFilter.class);
    
    private final RequestMatcher authorizationEndpointMatcher;
    private final AuthenticationConverter authenticationConverter;
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    
    public SsiOAuth2ValidationFilter() {
        this.authorizationEndpointMatcher = createDefaultRequestMatcher(DEFAULT_AUTHORIZATION_ENDPOINT_URI);
        this.authenticationConverter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!this.authorizationEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        
        OAuth2AuthorizationCodeRequestAuthenticationToken authToken =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) this.authenticationConverter.convert(request);
        if (authToken.getAdditionalParameters().get("request") != null) {
            sendErrorResponse(request, response, new OAuth2AuthorizationCodeRequestAuthenticationException(
                    new OAuth2Error("request_not_supported"), authToken));
        }

        filterChain.doFilter(request, response);
    }

    private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
        RequestMatcher authorizationRequestGetMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.GET.name());
        RequestMatcher authorizationRequestPostMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.POST.name());
        RequestMatcher openidScopeMatcher = request -> {
            String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
            return StringUtils.hasText(scope) && scope.contains(OidcScopes.OPENID);
        };
        RequestMatcher responseTypeParameterMatcher = request ->
                request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;

        RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(
                authorizationRequestGetMatcher,
                new AndRequestMatcher(
                        authorizationRequestPostMatcher, responseTypeParameterMatcher, openidScopeMatcher));
        RequestMatcher authorizationConsentMatcher = new AndRequestMatcher(
                authorizationRequestPostMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));

        return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
    }
    
    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException {

        OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestAuthenticationException =
                (OAuth2AuthorizationCodeRequestAuthenticationException) exception;
        OAuth2Error error = authorizationCodeRequestAuthenticationException.getError();
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                authorizationCodeRequestAuthenticationException.getAuthorizationCodeRequestAuthentication();

        if (authorizationCodeRequestAuthentication == null ||
                !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
            // TODO Send default html error response
            response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
            return;
        }

        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
                .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
        if (StringUtils.hasText(error.getDescription())) {
            uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
        }
        if (StringUtils.hasText(error.getUri())) {
            uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
        }
        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
            uriBuilder.queryParam(OAuth2ParameterNames.STATE, authorizationCodeRequestAuthentication.getState());
        }
        this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
    }
    
}
