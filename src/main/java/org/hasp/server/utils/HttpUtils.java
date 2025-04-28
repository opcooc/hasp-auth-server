package org.hasp.server.utils;

import jakarta.servlet.http.HttpServletRequest;
import okhttp3.*;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class HttpUtils {

    public static HttpServletRequest getHttpServletRequest() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new InternalAuthenticationServiceException("Failed to get the current request.");
        }
        return ((ServletRequestAttributes) requestAttributes).getRequest();
    }

}
