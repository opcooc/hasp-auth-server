package org.hasp.server.service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthUser;

import java.io.IOException;

public interface FederatedService {

    void authorize(HttpServletRequest request, HttpServletResponse response, String source, Boolean bind, String state) throws IOException;

    void callback(HttpServletRequest request, HttpServletResponse response, String source, AuthCallback callback) throws ServletException, IOException;

    void register(HttpServletRequest request, HttpServletResponse response, String username, String loginType, AuthUser authUser) throws ServletException, IOException;

    AuthResponse<?> revoke(HttpServletRequest request, HttpServletResponse response, String source);

}
