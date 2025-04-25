package org.hasp.server.entity;

import java.util.Set;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.core.GrantedAuthority;

@Data
@RedisHash("oauth2_authorization_consent")
public class OAuth2AuthorizationConsentEntity {

	@Id
	private String id;

	@Indexed
	private String registeredClientId;

	@Indexed
	private String principalName;

	private Set<GrantedAuthority> authorities;

}
