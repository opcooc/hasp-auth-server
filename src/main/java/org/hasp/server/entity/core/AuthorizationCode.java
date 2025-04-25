package org.hasp.server.entity.core;

import java.time.Instant;

public class AuthorizationCode extends AbstractToken {
    public AuthorizationCode(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated) {
        super(tokenValue, issuedAt, expiresAt, invalidated);
    }
}
