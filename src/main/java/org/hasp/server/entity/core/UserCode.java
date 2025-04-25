package org.hasp.server.entity.core;

import java.time.Instant;

public class UserCode extends AbstractToken {
    public UserCode(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated) {
        super(tokenValue, issuedAt, expiresAt, invalidated);
    }
}