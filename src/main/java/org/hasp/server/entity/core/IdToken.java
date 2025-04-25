package org.hasp.server.entity.core;

import lombok.Getter;

import java.time.Instant;

@Getter
public class IdToken extends AbstractToken {

    private final String claims;

    public IdToken(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated, String claims) {
        super(tokenValue, issuedAt, expiresAt, invalidated);
        this.claims = claims;
    }

}
