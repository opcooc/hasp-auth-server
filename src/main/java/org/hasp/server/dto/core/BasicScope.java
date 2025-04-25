package org.hasp.server.dto.core;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.hasp.server.utils.SecurityConstants;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

@Getter
@AllArgsConstructor
public enum BasicScope {
    /**
     * {@code scope} 含义，以{@code description} 为准
     */
    PROFILE(OidcScopes.PROFILE, "用户信息"),
    ADDRESS(OidcScopes.ADDRESS, "地址"),
    OPENID(OidcScopes.OPENID, "ID_TOKEN"),
    PHONE(OidcScopes.PHONE, "手机号"),
    CLIENT(SecurityConstants.CLIENT_SCOPE, "客户端管理"),
    USER(SecurityConstants.USER_SCOPE, "用户管理"),
    EMAIL(OidcScopes.EMAIL, "邮箱");

    private final String scope;
    private final String description;

    public static BasicScope fromScope(final String scope) {
        for (BasicScope item : BasicScope.values()) {
            if (item.scope.equals(scope)) {
                return item;
            }
        }
        return null;
    }
}
