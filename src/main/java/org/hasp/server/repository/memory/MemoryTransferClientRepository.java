package org.hasp.server.repository.memory;

import lombok.RequiredArgsConstructor;
import org.hasp.server.dto.TransferClient;
import org.hasp.server.dto.core.AppClientSettings;
import org.hasp.server.dto.core.AppTokenSettings;
import org.hasp.server.repository.core.TransferClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;

import java.time.Instant;
import java.util.Set;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class MemoryTransferClientRepository implements TransferClientRepository {

    private final PasswordEncoder passwordEncoder;

    @Override
    public void save(TransferClient client) {
    }

    @Override
    public TransferClient findById(String id) {
        return client();
    }

    @Override
    public TransferClient findByClientId(String clientId) {
        return client();
    }

    private TransferClient client() {
        return TransferClient.builder()
                .id("1862438268228636674")
                .clientId("demo")
                .clientIdIssuedAt(Instant.parse("2020-01-01T00:00:00Z"))
                .clientSecret(passwordEncoder.encode("demo"))
                .clientSecretExpiresAt(Instant.parse("2505-01-01T00:00:00Z"))
                .clientName("HASP Technology Co., Ltd")
                .clientAuthenticationMethods(Set.of(
                        ClientAuthenticationMethod.NONE.getValue(),
                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(),
                        ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()
                ))
                .authorizationGrantTypes(Set.of(
                        AuthorizationGrantType.REFRESH_TOKEN.getValue(),
                        AuthorizationGrantType.CLIENT_CREDENTIALS.getValue(),
                        AuthorizationGrantType.DEVICE_CODE.getValue(),
                        AuthorizationGrantType.AUTHORIZATION_CODE.getValue(),
                        AuthorizationGrantType.TOKEN_EXCHANGE.getValue(),
                        AuthorizationGrantType.JWT_BEARER.getValue()
                ))
                .redirectUris(Set.of(
                        "http://127.0.0.1:9527/home",
                        "http://127.0.0.1:9898/swagger-ui/oauth2-redirect.html"
                ))
                .postLogoutRedirectUris(Set.of("http://127.0.0.1:9527/login"))
                .scopes(Set.of("client.management", "user.management", "openid", "profile"))
                .clientSettings(AppClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(AppTokenSettings.builder()
                        .authorizationCodeTimeToLive(300L)
                        .accessTokenTimeToLive(86400L)
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED.getValue())
                        .deviceCodeTimeToLive(300L)
                        .reuseRefreshTokens(true)
                        .refreshTokenTimeToLive(259200L)
                        .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256.getName())
                        .build())
                .build();
    }
}
