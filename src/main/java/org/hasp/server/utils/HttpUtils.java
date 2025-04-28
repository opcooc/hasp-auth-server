package org.hasp.server.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class HttpUtils {

    public static HttpServletRequest getHttpServletRequest() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new InternalAuthenticationServiceException("Failed to get the current request.");
        }
        return ((ServletRequestAttributes) requestAttributes).getRequest();
    }

}
