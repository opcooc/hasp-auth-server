package org.hasp.server.support;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.util.*;

public class CustomOAuth2TokenCustomizers {

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	private CustomOAuth2TokenCustomizers() {
	}

	public static OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return (context) -> {
			Authentication principal = context.getPrincipal();

			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
					&& principal.getPrincipal() instanceof CustomUser user) {
				context.getClaims().claim(StandardClaimNames.SUB, user.getSubject());
			}

			if (ID_TOKEN_TOKEN_TYPE.equals(context.getTokenType())
					&& principal.getPrincipal() instanceof CustomUser user) {
				context.getClaims().claims(existingClaims ->
						existingClaims.putAll(getClaimsByScope(user.getClaims(), context.getAuthorizedScopes())));
			}
		};
	}

	public static Map<String, Object> getClaimsByScope(Map<String, Object> claims, Set<String> requestedScopes) {
		Set<String> scopeRequestedClaimNames = new HashSet<>(32);
		scopeRequestedClaimNames.add(StandardClaimNames.SUB);

		if (requestedScopes.contains(OidcScopes.ADDRESS)) {
			scopeRequestedClaimNames.add(StandardClaimNames.ADDRESS);
		}

		if (requestedScopes.contains(OidcScopes.EMAIL)) {
			scopeRequestedClaimNames.add(StandardClaimNames.EMAIL);
		}

		if (requestedScopes.contains(OidcScopes.PHONE)) {
			scopeRequestedClaimNames.add(StandardClaimNames.PHONE_NUMBER);
		}

		if (requestedScopes.contains(OidcScopes.PROFILE)) {
			scopeRequestedClaimNames.add(StandardClaimNames.NAME);
			scopeRequestedClaimNames.add(StandardClaimNames.NICKNAME);
			scopeRequestedClaimNames.add(StandardClaimNames.PICTURE);
			scopeRequestedClaimNames.add(StandardClaimNames.GENDER);
		}

		Map<String, Object> requestedClaims = new HashMap<>(claims);
		requestedClaims.keySet().removeIf(claimName -> !scopeRequestedClaimNames.contains(claimName));

		return requestedClaims;
	}

}
