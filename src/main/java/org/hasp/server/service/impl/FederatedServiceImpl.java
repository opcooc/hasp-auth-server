package org.hasp.server.service.impl;

import io.github.jayrobim.justauth.AuthRequestFactory;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Slf4j
@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class FederatedServiceImpl implements FederatedService {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final UserDetailsChecker authenticationChecks = new AccountStatusUserDetailsChecker();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private final AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private final AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler(SecurityConstants.OAUTH_SIGN_IN_PAGE_URI);
    private final TransferUserRepository transferUserRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final AuthRequestFactory factory;

    public void authorize(HttpServletRequest request, HttpServletResponse response, String source, Boolean bind, String state) throws IOException {
        try {
            state = bind ? String.format("bind_%s", state) : state;
            AuthRequest authRequest = factory.get(source);
            response.sendRedirect(authRequest.authorize(state));
        } catch (Exception ex) {
            log.error("Authorization Request failed", ex);
            response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
        }
    }

    public void callback(HttpServletRequest request, HttpServletResponse response, String source, AuthCallback callback) throws ServletException, IOException {
        try {
            AuthRequest authRequest = factory.get(source);
            AuthResponse<AuthUser> authResponse = authRequest.login(callback);

            if (!authResponse.ok()) {
                throw new InternalAuthenticationServiceException("authRequest.login error");
            }

            AuthUser authUser = authResponse.getData();

            if (callback.getState().startsWith("bind_")) {
                try {
                    transferUserRepository.register(UserMapper.toRegisterMap(authUser, "bind", null, null, null, SecurityUtils.getUserId()));
                    redirectStrategy.sendRedirect(request, response, SecurityConstants.OAUTH_FEDERATED_OUTCOME_PAGE_URI);
                } catch (Exception e) {
                    redirectStrategy.sendRedirect(request, response, SecurityConstants.OAUTH_FEDERATED_OUTCOME_PAGE_URI + "?error=" + e.getMessage());
                }
                return;
            }

            TransferUser user = transferUserRepository.load(authUser.getUuid(), source);
            if (user == null) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    request.getSession().setAttribute(SecurityConstants.AUTH_FEDERATED_USER, authUser);
                }
                redirectStrategy.sendRedirect(request, response, SecurityConstants.OAUTH_SIGN_UP_PAGE_URI);
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
                         String username, String loginType, AuthUser authUser) throws ServletException, IOException {
        try {
            try {
                transferUserRepository.register(UserMapper.toRegisterMap(authUser, "register", username, null, loginType, null));
            } catch (Exception e) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    request.getSession().setAttribute(SecurityConstants.AUTH_FEDERATED_USER, authUser);
                }
                redirectStrategy.sendRedirect(request, response, SecurityConstants.OAUTH_SIGN_UP_PAGE_URI);
                return;
            }

            TransferUser user = transferUserRepository.load(authUser.getUuid(), authUser.getSource());
            if (user == null) {
                throw new UsernameNotFoundException(username);
            }

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
        AuthRequest authRequest = factory.get(source);
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

}
