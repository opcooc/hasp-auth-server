package org.hasp.server.support;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

public class CustomOidcLogoutHandler implements LogoutHandler {

    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    private final CompositeLogoutHandler logoutHandler;
    private final OAuth2AuthorizationService authorizationService;

    public CustomOidcLogoutHandler(ApplicationEventPublisher eventPublisher, OAuth2AuthorizationService authorizationService) {
        SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();

        LogoutSuccessEventPublishingLogoutHandler logoutEventHandler = new LogoutSuccessEventPublishingLogoutHandler();
        logoutEventHandler.setApplicationEventPublisher(eventPublisher);

        this.logoutHandler = new CompositeLogoutHandler(securityContextLogoutHandler, logoutEventHandler);
        this.authorizationService = authorizationService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken) authentication;
        if (oidcLogoutAuthentication.isPrincipalAuthenticated()) {

            OAuth2Authorization authorization = authorizationService
                    .findByToken(oidcLogoutAuthentication.getIdTokenHint(), ID_TOKEN_TOKEN_TYPE);

            if (authorization == null) {
                throw new IllegalArgumentException("authorization is null, IdTokenHint :" + oidcLogoutAuthentication.getIdTokenHint());
            }

            OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization)
                    .invalidate(authorization.getAccessToken().getToken());
            if (authorization.getRefreshToken() != null) {
                builder.invalidate(authorization.getRefreshToken().getToken());
            }

            this.authorizationService.save(builder.build());

            this.logoutHandler.logout(request, response, (Authentication) oidcLogoutAuthentication.getPrincipal());
        }
    }
}
