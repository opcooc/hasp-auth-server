package org.hasp.server.dto.core;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AppTokenSettings {

    private Long authorizationCodeTimeToLive;
    private Long accessTokenTimeToLive;
    private Long refreshTokenTimeToLive;
    private Long deviceCodeTimeToLive;

    private String accessTokenFormat;
    private Boolean reuseRefreshTokens;
    private String idTokenSignatureAlgorithm;
    private Boolean x509CertificateBoundAccessTokens;
    
}
