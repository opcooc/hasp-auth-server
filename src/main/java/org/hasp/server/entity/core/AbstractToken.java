package org.hasp.server.entity.core;

import lombok.Getter;
import org.springframework.data.redis.core.index.Indexed;

import java.time.Instant;

@Getter
public abstract class AbstractToken {

    @Indexed
    private final String tokenValue;

    private final Instant issuedAt;

    private final Instant expiresAt;

    private final boolean invalidated;

    protected AbstractToken(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated) {
        this.tokenValue = tokenValue;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.invalidated = invalidated;
    }
}
