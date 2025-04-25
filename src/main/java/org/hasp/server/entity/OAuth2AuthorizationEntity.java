package org.hasp.server.entity;

import lombok.Data;
import org.hasp.server.entity.core.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Set;

@Data
@RedisHash("oauth2_authorization")
public class OAuth2AuthorizationEntity {

	@Id
	private String id;

	@Indexed
	private String state;

	@Indexed
	private String userId;

	@Indexed
	private String sessionId;

	private String registeredClientId;

	private String principalName;

	private AuthorizationGrantType authorizationGrantType;

	private Set<String> authorizedScopes;

	private String attributes;

	private AccessToken accessToken;

	private AuthorizationCode authorizationCode;

	private DeviceCode deviceCode;

	private RefreshToken refreshToken;

	private UserCode userCode;

	private IdToken idToken;

}
