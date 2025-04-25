package org.hasp.server.dto.core;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

@Getter
@AllArgsConstructor
public enum BasicScope {
    /**
     * ---
     */
    PROFILE(OidcScopes.PROFILE, "用户信息"),
    ADDRESS(OidcScopes.ADDRESS, "用户地址"),
    OPENID(OidcScopes.OPENID, "ID_TOKEN"),
    PHONE(OidcScopes.PHONE, "手机号"),
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
