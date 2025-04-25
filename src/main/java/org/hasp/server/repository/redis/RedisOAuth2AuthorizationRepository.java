package org.hasp.server.repository.redis;

import org.hasp.server.entity.OAuth2AuthorizationEntity;
import org.springframework.data.repository.CrudRepository;

public interface RedisOAuth2AuthorizationRepository extends CrudRepository<OAuth2AuthorizationEntity, String> {

	OAuth2AuthorizationEntity findByState(String state);

	OAuth2AuthorizationEntity findByAuthorizationCode_TokenValue(String authorizationCode);

	OAuth2AuthorizationEntity findByAccessToken_TokenValue(String accessToken);

	OAuth2AuthorizationEntity findByRefreshToken_TokenValue(String refreshToken);

	OAuth2AuthorizationEntity findByIdToken_TokenValue(String idToken);

	OAuth2AuthorizationEntity findByDeviceCode_TokenValue(String deviceCode);

	OAuth2AuthorizationEntity findByUserCode_TokenValue(String userCode);

}
