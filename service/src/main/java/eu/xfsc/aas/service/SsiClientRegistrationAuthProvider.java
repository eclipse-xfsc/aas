package eu.xfsc.aas.service;

import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.CollectionUtils;

import eu.xfsc.aas.model.SsiClientCustomClaims;

public class SsiClientRegistrationAuthProvider implements AuthenticationProvider {
	
	private SsiCorsConfigurationSource corsSource;
	private AuthenticationProvider delegate;
	
	public SsiClientRegistrationAuthProvider(SsiCorsConfigurationSource corsSource, AuthenticationProvider delegate) {
		this.corsSource = corsSource;
		this.delegate = delegate;
		((OidcClientRegistrationAuthenticationProvider) delegate).setRegisteredClientConverter(new SsiClientRegistrationRegisteredClientConverter());
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication auth = delegate.authenticate(authentication);
		if (auth != null) {
			// can check if new client adds any new CORS origins
			// can also pass new origins to corsSource to prevent fetch from DB
			//OidcClientRegistration cliReg = ((OidcClientRegistrationAuthenticationToken) auth).getClientRegistration();
			corsSource.invalidate();
		}
		return auth;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return delegate.supports(authentication);
	}

	// mostly copied from org.springframework.security.oauth2.server.authorization.oidc.authentication.
	//	OidcClientRegistrationAuthenticationProvider$OidcClientRegistrationRegisteredClientConverter
	private static final class SsiClientRegistrationRegisteredClientConverter implements Converter<OidcClientRegistration, RegisteredClient> {
		private static final StringKeyGenerator CLIENT_ID_GENERATOR = new Base64StringKeyGenerator(
				Base64.getUrlEncoder().withoutPadding(), 32);
		private static final StringKeyGenerator CLIENT_SECRET_GENERATOR = new Base64StringKeyGenerator(
				Base64.getUrlEncoder().withoutPadding(), 48);
		
		private static final Set<String> STANDARD_CLAIMS = Set.of("client_name", "token_endpoint_auth_method", "redirect_uris", "grant_types", 
				"response_types", "scope");

		@Override
		public RegisteredClient convert(OidcClientRegistration clientRegistration) {
			// @formatter:off
			RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
					.clientId(CLIENT_ID_GENERATOR.generateKey())
					.clientIdIssuedAt(Instant.now())
					.clientName(clientRegistration.getClientName());

			if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
				builder
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
						.clientSecret(CLIENT_SECRET_GENERATOR.generateKey());
			} else if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
				builder
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
						.clientSecret(CLIENT_SECRET_GENERATOR.generateKey());
			} else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
				builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
			} else {
				builder
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.clientSecret(CLIENT_SECRET_GENERATOR.generateKey());
			}

			builder.redirectUris(redirectUris ->
					redirectUris.addAll(clientRegistration.getRedirectUris()));

			if (!CollectionUtils.isEmpty(clientRegistration.getGrantTypes())) {
				builder.authorizationGrantTypes(authorizationGrantTypes ->
						clientRegistration.getGrantTypes().forEach(grantType ->
								authorizationGrantTypes.add(new AuthorizationGrantType(grantType))));
			} else {
				builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
			}
			if (CollectionUtils.isEmpty(clientRegistration.getResponseTypes()) ||
					clientRegistration.getResponseTypes().contains(OAuth2AuthorizationResponseType.CODE.getValue())) {
				builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
			}

			if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
				builder.scopes(scopes ->
						scopes.addAll(clientRegistration.getScopes()));
			}

			ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
					.requireProofKey(true)
					.requireAuthorizationConsent(true);

			if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
				MacAlgorithm macAlgorithm = MacAlgorithm.from(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm());
				if (macAlgorithm == null) {
					macAlgorithm = MacAlgorithm.HS256;
				}
				clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(macAlgorithm);
			} else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientRegistration.getTokenEndpointAuthenticationMethod())) {
				SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.from(clientRegistration.getTokenEndpointAuthenticationSigningAlgorithm());
				if (signatureAlgorithm == null) {
					signatureAlgorithm = SignatureAlgorithm.RS256;
				}
				clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(signatureAlgorithm);
				clientSettingsBuilder.jwkSetUrl(clientRegistration.getJwkSetUrl().toString());
			}

			// Add custom metadata claims
			boolean ssiAuthTypeFound[] = {false};
			clientRegistration.getClaims().forEach((claim, value) -> {
				if (!STANDARD_CLAIMS.contains(claim)) {
					clientSettingsBuilder.setting(claim, value);
					if (claim.equals(SsiClientCustomClaims.SSI_AUTH_TYPE)) {
						ssiAuthTypeFound[0] = true;
					}
				}
			});
			if (!ssiAuthTypeFound[0]) {
				clientSettingsBuilder.setting(SsiClientCustomClaims.SSI_AUTH_TYPE, SsiClientCustomClaims.AUTH_TYPE_OIDC);
			}
			
			builder
					.clientSettings(clientSettingsBuilder.build())
					.tokenSettings(TokenSettings.builder()
							.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
							.build());

			return builder.build();
			// @formatter:on
		}
	}
	
}
