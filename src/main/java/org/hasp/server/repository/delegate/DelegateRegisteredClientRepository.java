package org.hasp.server.repository.delegate;

import lombok.RequiredArgsConstructor;
import org.hasp.server.dto.TransferClient;
import org.hasp.server.dto.core.AppClientSettings;
import org.hasp.server.dto.core.AppTokenSettings;
import org.hasp.server.repository.core.TransferClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.JwaAlgorithm;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;

import java.time.Duration;
import java.util.Locale;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class DelegateRegisteredClientRepository implements RegisteredClientRepository {

    private final TransferClientRepository transferClientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        transferClientRepository.save(convertOAuth2RegisteredClient(registeredClient));
    }

    @Nullable
    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        TransferClient transferClient = transferClientRepository.findById(id);
        Assert.notNull(transferClient, "transferClient cannot be null");
        return convertRegisteredClient(transferClient);
    }

    @Nullable
    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        TransferClient transferClient = transferClientRepository.findByClientId(clientId);
        Assert.notNull(transferClient, "transferClient cannot be null");
        return convertRegisteredClient(transferClient);
    }


    private TransferClient convertOAuth2RegisteredClient(RegisteredClient registeredClient) {
        TransferClient result = new TransferClient();

        PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
        ClientSettings clientSettings = registeredClient.getClientSettings();
        TokenSettings tokenSettings = registeredClient.getTokenSettings();

        map.from(registeredClient::getId).to(result::setId);
        map.from(registeredClient::getClientId).to(result::setClientId);
        map.from(registeredClient::getClientIdIssuedAt).to(result::setClientIdIssuedAt);
        map.from(registeredClient::getClientSecret).to(result::setClientSecret);
        map.from(registeredClient::getClientSecretExpiresAt).to(result::setClientSecretExpiresAt);
        map.from(registeredClient::getClientName).to(result::setClientName);
        map.from(registeredClient.getClientAuthenticationMethods())
                .as(item -> item.stream().map(ClientAuthenticationMethod::getValue).collect(Collectors.toSet()))
                .to(result::setClientAuthenticationMethods);
        map.from(registeredClient.getAuthorizationGrantTypes())
                .as(item -> item.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toSet()))
                .to(result::setAuthorizationGrantTypes);
        map.from(registeredClient::getRedirectUris).to(result::setRedirectUris);
        map.from(registeredClient::getPostLogoutRedirectUris).to(result::setPostLogoutRedirectUris);
        map.from(registeredClient::getScopes).to(result::setScopes);

        AppClientSettings appClientSettings = new AppClientSettings();
        map.from(clientSettings::isRequireProofKey).to(appClientSettings::setRequireProofKey);
        map.from(clientSettings::isRequireAuthorizationConsent).to(appClientSettings::setRequireAuthorizationConsent);
        map.from(clientSettings::getJwkSetUrl).to(appClientSettings::setJwkSetUrl);
        map.from(clientSettings::getTokenEndpointAuthenticationSigningAlgorithm)
                .as(JwaAlgorithm::getName)
                .to(appClientSettings::setTokenEndpointAuthenticationSigningAlgorithm);
        map.from(clientSettings::getX509CertificateSubjectDN).to(appClientSettings::setX509CertificateSubjectDN);
        result.setClientSettings(appClientSettings);

        AppTokenSettings appTokenSettings = new AppTokenSettings();
        map.from(tokenSettings::getAuthorizationCodeTimeToLive).as(Duration::toSeconds).to(appTokenSettings::setAuthorizationCodeTimeToLive);
        map.from(tokenSettings::getAccessTokenTimeToLive).as(Duration::toSeconds).to(appTokenSettings::setAccessTokenTimeToLive);
        map.from(tokenSettings::getAccessTokenFormat).as(OAuth2TokenFormat::getValue).to(appTokenSettings::setAccessTokenFormat);
        map.from(tokenSettings::getDeviceCodeTimeToLive).as(Duration::toSeconds).to(appTokenSettings::setDeviceCodeTimeToLive);
        map.from(tokenSettings::isReuseRefreshTokens).to(appTokenSettings::setReuseRefreshTokens);
        map.from(tokenSettings::getRefreshTokenTimeToLive).as(Duration::toSeconds).to(appTokenSettings::setRefreshTokenTimeToLive);
        map.from(tokenSettings::getIdTokenSignatureAlgorithm).as(JwaAlgorithm::getName).to(appTokenSettings::setIdTokenSignatureAlgorithm);
        map.from(tokenSettings::isX509CertificateBoundAccessTokens).to(appTokenSettings::setX509CertificateBoundAccessTokens);
        result.setTokenSettings(appTokenSettings);

        return result;
    }

    private RegisteredClient convertRegisteredClient(TransferClient appClient) {
        PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();

        RegisteredClient.Builder builder = RegisteredClient.withId(appClient.getId());

        map.from(appClient::getClientId).to(builder::clientId);
        map.from(appClient::getClientIdIssuedAt).to(builder::clientIdIssuedAt);
        map.from(appClient::getClientSecret).to(builder::clientSecret);
        map.from(appClient::getClientSecretExpiresAt).to(builder::clientSecretExpiresAt);
        map.from(appClient::getClientName).to(builder::clientName);
        map.from(appClient.getClientAuthenticationMethods())
                .as(item -> item.stream().map(ClientAuthenticationMethod::new).collect(Collectors.toSet()))
                .to(item -> builder.clientAuthenticationMethods(consumer -> consumer.addAll(item)));
        map.from(appClient.getAuthorizationGrantTypes())
                .as(item -> item.stream().map(AuthorizationGrantType::new).collect(Collectors.toSet()))
                .to(item -> builder.authorizationGrantTypes(consumer -> consumer.addAll(item)));
        map.from(appClient::getRedirectUris).to(item -> builder.redirectUris(consumer -> consumer.addAll(item)));
        map.from(appClient::getPostLogoutRedirectUris).to(item -> builder.postLogoutRedirectUris(consumer -> consumer.addAll(item)));
        map.from(appClient::getScopes).to(item -> builder.scopes(consumer -> consumer.addAll(item)));

        AppClientSettings appClientSettings = appClient.getClientSettings();
        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder();
        map.from(appClientSettings::getRequireProofKey).to(clientSettingsBuilder::requireProofKey);
        map.from(appClientSettings::getRequireAuthorizationConsent).to(clientSettingsBuilder::requireAuthorizationConsent);
        map.from(appClientSettings::getJwkSetUrl).to(clientSettingsBuilder::jwkSetUrl);
        map.from(appClientSettings::getTokenEndpointAuthenticationSigningAlgorithm)
                .as(this::jwsAlgorithm)
                .to(clientSettingsBuilder::tokenEndpointAuthenticationSigningAlgorithm);
        map.from(appClientSettings::getX509CertificateSubjectDN).to(clientSettingsBuilder::x509CertificateSubjectDN);
        builder.clientSettings(clientSettingsBuilder.build());

        AppTokenSettings appTokenSettings = appClient.getTokenSettings();
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
        map.from(appTokenSettings::getAuthorizationCodeTimeToLive).as(Duration::ofSeconds).to(tokenSettingsBuilder::authorizationCodeTimeToLive);
        map.from(appTokenSettings::getAccessTokenTimeToLive).as(Duration::ofSeconds).to(tokenSettingsBuilder::accessTokenTimeToLive);
        map.from(appTokenSettings::getAccessTokenFormat).as(OAuth2TokenFormat::new).to(tokenSettingsBuilder::accessTokenFormat);
        map.from(appTokenSettings::getDeviceCodeTimeToLive).as(Duration::ofSeconds).to(tokenSettingsBuilder::deviceCodeTimeToLive);
        map.from(appTokenSettings::getReuseRefreshTokens).to(tokenSettingsBuilder::reuseRefreshTokens);
        map.from(appTokenSettings::getRefreshTokenTimeToLive).as(Duration::ofSeconds).to(tokenSettingsBuilder::refreshTokenTimeToLive);
        map.from(appTokenSettings::getIdTokenSignatureAlgorithm).as(this::signatureAlgorithm).to(tokenSettingsBuilder::idTokenSignatureAlgorithm);
        map.from(appTokenSettings::getX509CertificateBoundAccessTokens).to(tokenSettingsBuilder::x509CertificateBoundAccessTokens);
        builder.tokenSettings(tokenSettingsBuilder.build());

        return builder.build();
    }

    private JwsAlgorithm jwsAlgorithm(String signingAlgorithm) {
        String name = signingAlgorithm.toUpperCase(Locale.ROOT);
        JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.from(name);
        if (jwsAlgorithm == null) {
            jwsAlgorithm = MacAlgorithm.from(name);
        }
        return jwsAlgorithm;
    }

    private SignatureAlgorithm signatureAlgorithm(String signatureAlgorithm) {
        return SignatureAlgorithm.from(signatureAlgorithm.toUpperCase(Locale.ROOT));
    }
}
