package org.hasp.server.support;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.util.Assert;

import java.io.Serial;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

@Data
@EqualsAndHashCode(callSuper = false)
public class CustomUser implements StandardClaimAccessor, UserDetails {

    @Serial
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private static final String USERNAME_CLAIM_NAME = "username";
    private static final String PASSWORD_CLAIM_NAME = "password";
    private static final String STATUS_CLAIM_NAME = "status";
    private static final String DELETED_CLAIM_NAME = "deleted";
    private static final String AUTHORITIES_CLAIM_NAME = "authorities";
    private static final String CONTACT_CLAIM_NAME = "contact";

    private final Map<String, Object> claims;

    public CustomUser(Map<String, Object> claims) {
        Assert.notEmpty(claims, "claims cannot be empty");
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }
    
    @Override
    public String getUsername() {
        return this.getClaimAsString(USERNAME_CLAIM_NAME);
    }

    @Override
    public String getPassword() {
        return this.getClaimAsString(PASSWORD_CLAIM_NAME);
    }

    public Boolean isContact() {
        Boolean claim = this.getClaimAsBoolean(CONTACT_CLAIM_NAME);
        return claim != null && claim;
    }

    @Override
    public Set<GrantedAuthority> getAuthorities() {
        return this.getClaim(AUTHORITIES_CLAIM_NAME);
    }

    @Override
    public boolean isEnabled() {
        // 用户状态 0：有效 1：锁定 2：禁用
//        Integer status = this.getClaim(STATUS_CLAIM_NAME);
        // 是否删除
//        Boolean deleted = this.getClaimAsBoolean(DELETED_CLAIM_NAME);
        return true;
    }

    public static CustomUser.Builder builder() {
        return new CustomUser.Builder();
    }

    public static final class Builder {

        private final Map<String, Object> claims = new LinkedHashMap<>();

        private Builder() {
        }

        public CustomUser.Builder claim(String name, Object value) {
            this.claims.put(name, value);
            return this;
        }

        public CustomUser.Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
            claimsConsumer.accept(this.claims);
            return this;
        }

        public CustomUser.Builder subject(String subject) {
            return this.claim(StandardClaimNames.SUB, subject);
        }

        public CustomUser.Builder name(String name) {
            return claim(StandardClaimNames.NAME, name);
        }

        public CustomUser.Builder username(String username) {
            return claim(USERNAME_CLAIM_NAME, username);
        }


        public CustomUser.Builder password(String password) {
            return claim(PASSWORD_CLAIM_NAME, password);
        }

        public CustomUser.Builder contact(Boolean contact) {
            return claim(CONTACT_CLAIM_NAME, contact);
        }

        public CustomUser.Builder nickname(String nickname) {
            return claim(StandardClaimNames.NICKNAME, nickname);
        }

        public CustomUser.Builder status(Integer status) {
            return claim(STATUS_CLAIM_NAME, status);
        }

        public CustomUser.Builder deleted(Boolean deleted) {
            return claim(DELETED_CLAIM_NAME, deleted);
        }

        public CustomUser.Builder authorities(Set<SimpleGrantedAuthority> authorities) {
            return claim(AUTHORITIES_CLAIM_NAME, Collections.unmodifiableSet(authorities));
        }

        public CustomUser.Builder address(String address) {
            return this.claim(StandardClaimNames.ADDRESS, address);
        }

        public CustomUser.Builder birthdate(String birthdate) {
            return this.claim(StandardClaimNames.BIRTHDATE, birthdate);
        }

        public CustomUser.Builder email(String email) {
            return this.claim(StandardClaimNames.EMAIL, email);
        }

        public CustomUser.Builder emailVerified(Boolean emailVerified) {
            return this.claim(StandardClaimNames.EMAIL_VERIFIED, emailVerified);
        }

        public CustomUser.Builder familyName(String familyName) {
            return claim(StandardClaimNames.FAMILY_NAME, familyName);
        }

        public CustomUser.Builder gender(String gender) {
            return this.claim(StandardClaimNames.GENDER, gender);
        }

        public CustomUser.Builder givenName(String givenName) {
            return claim(StandardClaimNames.GIVEN_NAME, givenName);
        }

        public CustomUser.Builder locale(String locale) {
            return this.claim(StandardClaimNames.LOCALE, locale);
        }

        public CustomUser.Builder middleName(String middleName) {
            return claim(StandardClaimNames.MIDDLE_NAME, middleName);
        }

        public CustomUser.Builder picture(String picture) {
            return this.claim(StandardClaimNames.PICTURE, picture);
        }

        public CustomUser.Builder phoneNumber(String phoneNumber) {
            return this.claim(StandardClaimNames.PHONE_NUMBER, phoneNumber);
        }

        public CustomUser.Builder phoneNumberVerified(Boolean phoneNumberVerified) {
            return this.claim(StandardClaimNames.PHONE_NUMBER_VERIFIED, phoneNumberVerified);
        }

        public CustomUser.Builder preferredUsername(String preferredUsername) {
            return claim(StandardClaimNames.PREFERRED_USERNAME, preferredUsername);
        }

        public CustomUser.Builder profile(String profile) {
            return claim(StandardClaimNames.PROFILE, profile);
        }


        public CustomUser.Builder updatedAt(String updatedAt) {
            return this.claim(StandardClaimNames.UPDATED_AT, updatedAt);
        }

        public CustomUser.Builder website(String website) {
            return this.claim(StandardClaimNames.WEBSITE, website);
        }

        public CustomUser.Builder zoneinfo(String zoneinfo) {
            return this.claim(StandardClaimNames.ZONEINFO, zoneinfo);
        }

        public CustomUser build() {
            return new CustomUser(this.claims);
        }

    }

}
