package org.hasp.server.event;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hasp.server.support.CustomUser;
import org.hasp.server.utils.SecurityUtils;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent;

import java.security.Principal;

@Slf4j
@RequiredArgsConstructor
public class AuthenticationEventListener {

    private final OAuth2AuthorizationService authorizationService;

    @EventListener
    public void onLoginSuccess(AuthenticationSuccessEvent event) {
        if (event.getAuthentication() instanceof UsernamePasswordAuthenticationToken
                && event.getAuthentication().getPrincipal() instanceof CustomUser user) {
            log.info("用户[{}]登录成功....", user.getSubject());
        }

        if (event.getAuthentication() instanceof OAuth2AccessTokenAuthenticationToken token) {
            OAuth2Authorization authorization = authorizationService.findByToken(token.getAccessToken().getTokenValue(), OAuth2TokenType.ACCESS_TOKEN);
            if (authorization == null) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
            }

            String userId = SecurityUtils.getUser(authorization.getAttribute(Principal.class.getName())).getSubject();
            log.info("用户[{}]授权应用[{}]成功, AccessToken:[{}], RefreshToken:[{}], IdToken:[{}]....",
                    userId,
                    token.getRegisteredClient().getClientId(),
                    token.getAccessToken().getTokenValue(),
                    token.getRefreshToken() != null ? token.getRefreshToken().getTokenValue() : "",
                    token.getAdditionalParameters() != null ? token.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN) : "");
        }
    }

    @EventListener
    public void onSessionFixationProtection(SessionFixationProtectionEvent event) {
        log.info("会话保护 {} to {}.... ", event.getOldSessionId(), event.getNewSessionId());
    }

    @EventListener
    public void onLogoutSuccess(SessionDestroyedEvent event) {
        // 当用户登出(会话过期)时触发，用于更新用户的登录状态、清除缓存、记录日志等。
        // LogoutSuccessEvent 用户登出时触发，当前平台使用session所以当前事件不做处理
        for (SecurityContext securityContext : event.getSecurityContexts()) {
            if (securityContext.getAuthentication().getPrincipal() instanceof CustomUser user) {
                log.info("用户[{}]退出登录或状态过期....{}", user.getSubject(), event.getId());
            }
        }
    }

    @EventListener
    public void onLoginFailure(AuthenticationFailureBadCredentialsEvent event) {
        // 当认证失败，尤其是由于错误的凭证（用户名/密码错误）时触发, 用于记录认证失败的详细信息，比如用户名/密码错误、账户锁定等。
        // BadCredentialsException AuthenticationFailureBadCredentialsEvent
        //UsernameNotFoundException AuthenticationFailureBadCredentialsEvent
        //AccountExpiredException AuthenticationFailureExpiredEvent
        //ProviderNotFoundException AuthenticationFailureProviderNotFoundEvent
        //DisabledException AuthenticationFailureDisabledEvent
        //LockedException AuthenticationFailureLockedEvent
        //AuthenticationServiceException AuthenticationFailureServiceExceptionEvent
        //CredentialsExpiredException AuthenticationFailureCredentialsExpiredEvent
        //InvalidBearerTokenException AuthenticationFailureBadCredentialsEvent
        log.info("用户登录失败....{}", event.getAuthentication());
    }

}
