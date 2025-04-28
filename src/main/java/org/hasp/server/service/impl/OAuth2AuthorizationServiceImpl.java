package org.hasp.server.service.impl;

import lombok.RequiredArgsConstructor;
import org.hasp.server.entity.OAuth2AuthorizationEntity;
import org.hasp.server.entity.core.*;
import org.hasp.server.repository.redis.RedisOAuth2AuthorizationRepository;
import org.hasp.server.support.CustomUser;
import org.hasp.server.utils.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.Map;

@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class OAuth2AuthorizationServiceImpl implements OAuth2AuthorizationService {

    private final RegisteredClientRepository registeredClientRepository;

    private final RedisOAuth2AuthorizationRepository redisOAuth2AuthorizationRepository;

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2AuthorizationEntity authorizationGrantAuthorization = convertOAuth2Authorization(authorization);
        this.redisOAuth2AuthorizationRepository.save(authorizationGrantAuthorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        this.redisOAuth2AuthorizationRepository.deleteById(authorization.getId());
    }

    @Nullable
    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return this.redisOAuth2AuthorizationRepository.findById(id).map(this::toOAuth2Authorization).orElse(null);
    }

    @Nullable
    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        OAuth2AuthorizationEntity authorizationGrantAuthorization = null;
        if (tokenType == null) {
            authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByState(token);
            if (authorizationGrantAuthorization == null) {
                authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByAuthorizationCode_TokenValue(token);
            }
            if (authorizationGrantAuthorization == null) {
                authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByAccessToken_TokenValue(token);
            }
            if (authorizationGrantAuthorization == null) {
                authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByIdToken_TokenValue(token);
            }
            if (authorizationGrantAuthorization == null) {
                authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByRefreshToken_TokenValue(token);
            }
            if (authorizationGrantAuthorization == null) {
                authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByUserCode_TokenValue(token);
            }
            if (authorizationGrantAuthorization == null) {
                authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByDeviceCode_TokenValue(token);
            }
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByAuthorizationCode_TokenValue(token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByAccessToken_TokenValue(token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByIdToken_TokenValue(token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByRefreshToken_TokenValue(token);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByUserCode_TokenValue(token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            authorizationGrantAuthorization = this.redisOAuth2AuthorizationRepository.findByDeviceCode_TokenValue(token);
        }
        return authorizationGrantAuthorization != null ? toOAuth2Authorization(authorizationGrantAuthorization) : null;
    }

    private OAuth2Authorization toOAuth2Authorization(OAuth2AuthorizationEntity authorization) {
        RegisteredClient registeredClient = this.registeredClientRepository.findById(authorization.getRegisteredClientId());
        return mapOAuth2Authorization(authorization, registeredClient);
    }

    private static OAuth2AuthorizationEntity convertOAuth2Authorization(OAuth2Authorization authorization) {

        OAuth2AuthorizationEntity result = new OAuth2AuthorizationEntity();
        result.setId(authorization.getId());
        result.setRegisteredClientId(authorization.getRegisteredClientId());
        result.setPrincipalName(authorization.getPrincipalName());
        result.setAuthorizationGrantType(authorization.getAuthorizationGrantType());
        result.setAuthorizedScopes(authorization.getAuthorizedScopes());
        result.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));
        result.setAttributes(JsonUtils.toJsonString(authorization.getAttributes()));

        if (authorization.getAttribute(Principal.class.getName()) instanceof UsernamePasswordAuthenticationToken token
                && token.getPrincipal() instanceof CustomUser user) {
            result.setUserId(user.getSubject());
        }

        OAuth2Authorization.Token<OAuth2AccessToken> oauth2AccessToken = authorization.getAccessToken();
        if (oauth2AccessToken != null) {

            OAuth2TokenFormat tokenFormat = null;
            if (OAuth2TokenFormat.SELF_CONTAINED.getValue()
                    .equals(oauth2AccessToken.getMetadata(OAuth2TokenFormat.class.getName()))) {
                tokenFormat = OAuth2TokenFormat.SELF_CONTAINED;
            } else if (OAuth2TokenFormat.REFERENCE.getValue()
                    .equals(oauth2AccessToken.getMetadata(OAuth2TokenFormat.class.getName()))) {
                tokenFormat = OAuth2TokenFormat.REFERENCE;
            }

            result.setAccessToken(new AccessToken(
                    oauth2AccessToken.getToken().getTokenValue(),
                    oauth2AccessToken.getToken().getIssuedAt(),
                    oauth2AccessToken.getToken().getExpiresAt(),
                    oauth2AccessToken.isInvalidated(),
                    oauth2AccessToken.getToken().getTokenType(),
                    oauth2AccessToken.getToken().getScopes(),
                    tokenFormat,
                    JsonUtils.toJsonString(oauth2AccessToken.getClaims())
            ));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> oauth2RefreshToken = authorization.getRefreshToken();
        if (oauth2RefreshToken != null) {
            result.setRefreshToken(new RefreshToken(
                    oauth2RefreshToken.getToken().getTokenValue(),
                    oauth2RefreshToken.getToken().getIssuedAt(),
                    oauth2RefreshToken.getToken().getExpiresAt(),
                    oauth2RefreshToken.isInvalidated()
            ));
        }

        OAuth2Authorization.Token<OAuth2AuthorizationCode> oauth2AuthorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        if (oauth2AuthorizationCode != null) {
            result.setAuthorizationCode(new AuthorizationCode(
                    oauth2AuthorizationCode.getToken().getTokenValue(),
                    oauth2AuthorizationCode.getToken().getIssuedAt(),
                    oauth2AuthorizationCode.getToken().getExpiresAt(),
                    oauth2AuthorizationCode.isInvalidated()
            ));
        }

        OAuth2Authorization.Token<OAuth2DeviceCode> oauth2DeviceCode = authorization.getToken(OAuth2DeviceCode.class);
        if (oauth2DeviceCode != null) {
            result.setDeviceCode(new DeviceCode(
                    oauth2DeviceCode.getToken().getTokenValue(),
                    oauth2DeviceCode.getToken().getIssuedAt(),
                    oauth2DeviceCode.getToken().getExpiresAt(),
                    oauth2DeviceCode.isInvalidated()
            ));
        }

        OAuth2Authorization.Token<OAuth2UserCode> oauth2UserCode = authorization.getToken(OAuth2UserCode.class);
        if (oauth2UserCode != null) {
            result.setUserCode(new UserCode(
                    oauth2UserCode.getToken().getTokenValue(),
                    oauth2UserCode.getToken().getIssuedAt(),
                    oauth2UserCode.getToken().getExpiresAt(),
                    oauth2UserCode.isInvalidated()
            ));
        }

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            result.setIdToken(new IdToken(
                    oidcIdToken.getToken().getTokenValue(),
                    oidcIdToken.getToken().getIssuedAt(),
                    oidcIdToken.getToken().getExpiresAt(),
                    oidcIdToken.isInvalidated(),
                    JsonUtils.toJsonString(oidcIdToken.getClaims())
            ));
        }

        return result;
    }

    private static OAuth2Authorization mapOAuth2Authorization(OAuth2AuthorizationEntity authorization, RegisteredClient registeredClient) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(authorization.getId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType())
                .authorizedScopes(authorization.getAuthorizedScopes())
                .attributes(consumer -> consumer.putAll(JsonUtils.fromMap(authorization.getAttributes())));

        if (authorization.getAccessToken() != null) {
            AccessToken accessToken = authorization.getAccessToken();

            OAuth2AccessToken oauth2AccessToken = new OAuth2AccessToken(
                    accessToken.getTokenType(),
                    accessToken.getTokenValue(),
                    accessToken.getIssuedAt(),
                    accessToken.getExpiresAt(),
                    accessToken.getScopes());

            builder.token(oauth2AccessToken, (metadata) -> {
                metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, accessToken.isInvalidated());
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, JsonUtils.fromMap(accessToken.getClaims()));
                metadata.put(OAuth2TokenFormat.class.getName(), accessToken.getTokenFormat().getValue());
            });
        }

        if (authorization.getRefreshToken() != null) {
            RefreshToken refreshToken = authorization.getRefreshToken();

            OAuth2RefreshToken oauth2RefreshToken = new OAuth2RefreshToken(
                    refreshToken.getTokenValue(),
                    refreshToken.getIssuedAt(),
                    refreshToken.getExpiresAt());

            builder.token(oauth2RefreshToken, (metadata) -> metadata
                    .put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, refreshToken.isInvalidated()));
        }

        if (authorization.getAuthorizationCode() != null) {
            AuthorizationCode authorizationCode = authorization.getAuthorizationCode();

            OAuth2AuthorizationCode oauth2AuthorizationCode = new OAuth2AuthorizationCode(
                    authorizationCode.getTokenValue(),
                    authorizationCode.getIssuedAt(),
                    authorizationCode.getExpiresAt());

            builder.token(oauth2AuthorizationCode, (metadata) -> metadata
                    .put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, authorizationCode.isInvalidated()));
        }

        if (authorization.getDeviceCode() != null) {
            DeviceCode deviceCode = authorization.getDeviceCode();

            OAuth2DeviceCode oauth2DeviceCode = new OAuth2DeviceCode(
                    deviceCode.getTokenValue(),
                    deviceCode.getIssuedAt(),
                    deviceCode.getExpiresAt());

            builder.token(oauth2DeviceCode, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, deviceCode.isInvalidated()));
        }

        if (authorization.getUserCode() != null) {
            UserCode userCode = authorization.getUserCode();

            OAuth2UserCode oauth2UserCode = new OAuth2UserCode(
                    userCode.getTokenValue(),
                    userCode.getIssuedAt(),
                    userCode.getExpiresAt());

            builder.token(oauth2UserCode, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, userCode.isInvalidated()));
        }

        if (authorization.getIdToken() != null) {
            IdToken idToken = authorization.getIdToken();
            Map<String, Object> claims = JsonUtils.fromMap(idToken.getClaims());
            OidcIdToken oidcIdToken = new OidcIdToken(
                    idToken.getTokenValue(),
                    idToken.getIssuedAt(),
                    idToken.getExpiresAt(),
                    claims);

            builder.token(oidcIdToken, (metadata) -> {
                metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, idToken.isInvalidated());
                metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
            });
        }
        return builder.build();
    }
}
