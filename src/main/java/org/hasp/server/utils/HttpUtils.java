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

    private final OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build();

    public String doGet(String url) throws IOException {
        Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer token")
                .get()
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("请求失败: " + response.code());
            }
            return response.body().string();
        }
    }

    public String doPostJson(String url, Object data) throws IOException {
        String json = JsonUtils.toJsonString(data);

        RequestBody body = RequestBody.create(
                json, MediaType.get(org.springframework.http.MediaType.APPLICATION_JSON_VALUE));

        Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer token")
                .post(body)
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("请求失败: " + response.code() + " " + response.message());
            }
            return response.body().string();
        }
    }

    public static HttpServletRequest getHttpServletRequest() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new InternalAuthenticationServiceException("Failed to get the current request.");
        }
        return ((ServletRequestAttributes) requestAttributes).getRequest();
    }

}
