package org.hasp.server.service.impl;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.AuthRequestBuilder;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthRequest;
import org.hasp.server.dto.TransferUser;
import org.hasp.server.mapper.UserMapper;
import org.hasp.server.repository.core.TransferUserRepository;
import org.hasp.server.service.FederatedService;
import org.hasp.server.support.CustomUser;
import org.hasp.server.utils.SecurityConstants;
import org.hasp.server.utils.SecurityUtils;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;

@Slf4j
@Service
@RequiredArgsConstructor
public class FederatedServiceImpl implements FederatedService {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final UserDetailsChecker authenticationChecks = new AccountStatusUserDetailsChecker();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private final AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private final AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler(SecurityConstants.OAUTH_SIGN_IN_PAGE_URI);
    private final TransferUserRepository transferUserRepository;
    private final StringRedisTemplate redisTemplate;
    private final ApplicationEventPublisher eventPublisher;

    public void authorize(HttpServletRequest request, HttpServletResponse response, String source, Boolean bind, String state) throws IOException {
        try {
            state = bind ? String.format("bind_%s", state) : state;
            AuthRequest authRequest = builderAuthRequest(source);
            response.sendRedirect(authRequest.authorize(state));
        } catch (Exception ex) {
            log.error("Authorization Request failed", ex);
            response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
        }
    }

    public void callback(HttpServletRequest request, HttpServletResponse response, String source, AuthCallback callback) throws ServletException, IOException {
        try {
            AuthRequest authRequest = builderAuthRequest(source);
            AuthResponse<AuthUser> authResponse = authRequest.login(callback);

            if (!authResponse.ok()) {
                throw new InternalAuthenticationServiceException("authRequest.login error");
            }

            AuthUser authUser = authResponse.getData();

            if (callback.getState().startsWith("bind_")) {
                try {
                    transferUserRepository.register(UserMapper.toRegisterMap(authUser, "bind", null, null, null, SecurityUtils.getUserId()));
                    redirectStrategy.sendRedirect(request, response, SecurityConstants.OAUTH_EXTERNAL_OUTCOME_PAGE_URI);
                } catch (InternalAuthenticationServiceException e) {
                    redirectStrategy.sendRedirect(request, response, SecurityConstants.OAUTH_EXTERNAL_OUTCOME_PAGE_URI + "?error=" + e.getMessage());
                }
                return;
            }

            TransferUser user = transferUserRepository.load(authUser.getUuid(), source);
            if (user == null) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    request.getSession().setAttribute(SecurityConstants.AUTH_FEDERATED_USER, authUser);
                }
                redirectStrategy.sendRedirect(request, response, SecurityConstants.OAUTH_EXTERNAL_REGISTER_URI);
                return;
            }

            CustomUser customUser = UserMapper.toCustomUser(user, true);
            authenticationChecks.check(customUser);
            UsernamePasswordAuthenticationToken authenticationResult = new UsernamePasswordAuthenticationToken(customUser, null, customUser.getAuthorities());
            authenticationResult.setDetails(this.authenticationDetailsSource.buildDetails(request));

            successfulAuthentication(request, response, authenticationResult);
        } catch (InternalAuthenticationServiceException failed) {
            log.error("An internal error occurred while trying to authenticate the user.", failed);
            unsuccessfulAuthentication(request, response, failed);
        } catch (AuthenticationException ex) {
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    @Override
    public void register(HttpServletRequest request, HttpServletResponse response,
                         String username, String password, String loginType, AuthUser authUser) throws ServletException, IOException {
        try {
            try {
                transferUserRepository.register(UserMapper.toRegisterMap(authUser, "register", username, password, loginType, null));
            } catch (InternalAuthenticationServiceException e) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    request.getSession().setAttribute(SecurityConstants.AUTH_FEDERATED_USER, authUser);
                }
                redirectStrategy.sendRedirect(request, response, SecurityConstants.OAUTH_EXTERNAL_REGISTER_URI);
                return;
            }

            TransferUser user = transferUserRepository.load(authUser.getUuid(), authUser.getSource());
            CustomUser customUser = UserMapper.toCustomUser(user, true);
            authenticationChecks.check(customUser);
            UsernamePasswordAuthenticationToken authenticationResult =
                    new UsernamePasswordAuthenticationToken(customUser, null, customUser.getAuthorities());
            authenticationResult.setDetails(this.authenticationDetailsSource.buildDetails(request));

            successfulAuthentication(request, response, authenticationResult);
        } catch (InternalAuthenticationServiceException failed) {
            log.error("An internal error occurred while trying to authenticate the user.", failed);
            unsuccessfulAuthentication(request, response, failed);
        } catch (AuthenticationException ex) {
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    public AuthResponse<?> revoke(HttpServletRequest request, HttpServletResponse response, String source) {
        AuthRequest authRequest = builderAuthRequest(source);
        // todo 获取账户的联合登录token信息
        return authRequest.revoke(AuthToken.builder().accessToken(null).build());
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {
        SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authResult);
        this.securityContextHolderStrategy.setContext(context);
        this.securityContextRepository.saveContext(context, request, response);
        log.debug("Set SecurityContextHolder to {}", authResult);
        if (this.eventPublisher != null) {
            this.eventPublisher.publishEvent(new AuthenticationSuccessEvent(authResult));
        }
        this.successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        this.securityContextHolderStrategy.clearContext();
        log.trace("Failed to process authentication request", failed);
        log.trace("Cleared SecurityContextHolder");
        log.trace("Handling authentication failure");
        this.failureHandler.onAuthenticationFailure(request, response, failed);
    }

    private AuthRequest builderAuthRequest(String source) {
        return AuthRequestBuilder.builder().source(source).authConfig((providerCode) -> {
            // todo 通过配置文件获取
            return null;
        }).authStateCache(new AuthStateCache() {
            @Override
            public void cache(String key, String value) {
                redisTemplate.opsForValue().set(rowKey(key), value, Duration.ofMinutes(5L));
            }

            @Override
            public void cache(String key, String value, long timeout) {
                redisTemplate.opsForValue().set(rowKey(key), value, Duration.ofMillis(timeout));
            }

            @Override
            public String get(String key) {
                return redisTemplate.opsForValue().get(rowKey(key));
            }

            @Override
            public boolean containsKey(String key) {
                Boolean b = redisTemplate.hasKey(rowKey(key));
                return b != null && b;
            }

            private String rowKey(String key) {
                return String.format("federated:%s", key);
            }
        }).build();
    }

}
