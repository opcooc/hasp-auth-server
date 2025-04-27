package org.hasp.server.service.impl;

import lombok.RequiredArgsConstructor;
import org.hasp.server.entity.OAuth2AuthorizationConsentEntity;
import org.hasp.server.repository.redis.RedisOAuth2AuthorizationConsentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class OAuth2AuthorizationConsentServiceImpl implements OAuth2AuthorizationConsentService {

    private final RedisOAuth2AuthorizationConsentRepository redisOAuth2AuthorizationConsentRepository;

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        OAuth2AuthorizationConsentEntity oauth2UserConsent = convertOAuth2AuthorizationConsent(authorizationConsent);
        this.redisOAuth2AuthorizationConsentRepository.save(oauth2UserConsent);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
        this.redisOAuth2AuthorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
                authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName()
        );
    }

    @Nullable
    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        OAuth2AuthorizationConsentEntity oauth2UserConsent = this.redisOAuth2AuthorizationConsentRepository
                .findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName);
        return oauth2UserConsent != null ? mapOAuth2AuthorizationConsent(oauth2UserConsent) : null;
    }

    private static OAuth2AuthorizationConsent mapOAuth2AuthorizationConsent(OAuth2AuthorizationConsentEntity userConsent) {
        return OAuth2AuthorizationConsent.withId(userConsent.getRegisteredClientId(), userConsent.getPrincipalName())
                .authorities((authorities) -> authorities.addAll(userConsent.getAuthorities()))
                .build();
    }


    private static OAuth2AuthorizationConsentEntity convertOAuth2AuthorizationConsent(OAuth2AuthorizationConsent authorizationConsent) {
        String id = authorizationConsent.getRegisteredClientId().concat("-").concat(authorizationConsent.getPrincipalName());
        OAuth2AuthorizationConsentEntity result = new OAuth2AuthorizationConsentEntity();
        result.setId(id);
        result.setAuthorities(authorizationConsent.getAuthorities());
        result.setPrincipalName(authorizationConsent.getPrincipalName());
        result.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
        return result;
    }
}
