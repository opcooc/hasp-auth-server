package org.hasp.server.repository.redis;

import org.hasp.server.entity.OAuth2AuthorizationConsentEntity;
import org.springframework.data.repository.CrudRepository;

public interface RedisOAuth2AuthorizationConsentRepository extends CrudRepository<OAuth2AuthorizationConsentEntity, String> {

	OAuth2AuthorizationConsentEntity findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

	void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

}
