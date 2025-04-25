package org.hasp.server.entity.core;

import java.time.Instant;

public class DeviceCode extends AbstractToken {
    public DeviceCode(String tokenValue, Instant issuedAt, Instant expiresAt, boolean invalidated) {
        super(tokenValue, issuedAt, expiresAt, invalidated);
    }
}