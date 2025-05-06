package org.hasp.server.utils;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.hasp.server.support.CustomUser;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Optional;

@Slf4j
public class SecurityUtils {

    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static CustomUser getUser() {
        return getUserOpt().orElseThrow(() -> new IllegalArgumentException("用户信息不存在"));
    }

    public static Optional<CustomUser> getUserOpt() {
        return getUserOpt(getAuthentication());
    }

    public static CustomUser getUser(Authentication authentication) {
        return getUserOpt(authentication).orElseThrow(() -> new IllegalArgumentException("用户信息不存在"));
    }

    public static Optional<CustomUser> getUserOpt(Authentication authentication) {
        if (authentication == null) {
            return Optional.empty();
        }
        if (authentication.getPrincipal() instanceof Jwt user) {
            return Optional.of(new CustomUser(user.getClaims()));
        }
        if (authentication.getPrincipal() instanceof CustomUser user) {
            return Optional.of(user);
        }
        return Optional.empty();
    }

    public static String getUserId() {
        return getUser().getSubject();
    }

    public static HttpServletRequest getHttpServletRequest() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new InternalAuthenticationServiceException("Failed to get the current request.");
        }
        return ((ServletRequestAttributes) requestAttributes).getRequest();
    }

}
