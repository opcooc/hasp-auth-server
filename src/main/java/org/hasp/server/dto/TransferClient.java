package org.hasp.server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hasp.server.dto.core.AppClientSettings;
import org.hasp.server.dto.core.AppTokenSettings;

import java.time.Instant;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransferClient {

    /**
     * ID
     */
    private String id;

    /**
     * 客户端ID
     */
    private String clientId;

    /**
     * 客户端ID颁发时间
     */
    private Instant clientIdIssuedAt;

    /**
     * 客户端密钥
     */
    private String clientSecret;

    /**
     * 客户端密钥过期时间
     */
    private Instant clientSecretExpiresAt;

    /**
     * 客户端名称
     */
    private String clientName;

    /**
     * 客户端认证方式的集合
     */
    private Set<String> clientAuthenticationMethods;

    /**
     * 授权许可类型的集合
     */
    private Set<String> authorizationGrantTypes;

    /**
     * 重定向URI的集合
     */
    private Set<String> redirectUris;

    /**
     * 登出后重定向URI的集合
     */
    private Set<String> postLogoutRedirectUris;

    /**
     * 授权范围的集合
     */
    private Set<String> scopes;

    /**
     * 客户端设置
     */
    private AppClientSettings clientSettings;

    /**
     * 令牌设置
     */
    private AppTokenSettings tokenSettings;

}
