package org.hasp.server.entity.core;

import java.time.Instant;

public class RefreshToken extends AbstractToken {
    public RefreshToken(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated) {
        super(tokenValue, issuedAt, expiresAt, invalidated);
    }
}