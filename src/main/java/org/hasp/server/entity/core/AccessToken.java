package org.hasp.server.entity.core;

import lombok.Getter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

import java.time.Instant;
import java.util.Set;

@Getter
public class AccessToken extends AbstractToken {

    private final OAuth2AccessToken.TokenType tokenType;

    private final Set<String> scopes;

    private final OAuth2TokenFormat tokenFormat;

    private final String claims;

    public AccessToken(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated,
                       OAuth2AccessToken.TokenType tokenType, Set<String> scopes, OAuth2TokenFormat tokenFormat,
                       String claims) {
        super(tokenValue, issuedAt, expiresAt, invalidated);
        this.tokenType = tokenType;
        this.scopes = scopes;
        this.tokenFormat = tokenFormat;
        this.claims = claims;
    }
}
