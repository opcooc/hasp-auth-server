package org.hasp.server.mapper;


import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import org.hasp.server.dto.TransferUser;
import org.hasp.server.support.CustomUser;
import org.hasp.server.utils.SecurityConstants;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class UserMapper {

    public static CustomUser toCustomUser(TransferUser user, Boolean contact) {

        return CustomUser.builder()

                .address(user.getAddress())
                .birthdate(user.getBirthdate())
                .email(user.getEmail())
                .emailVerified(user.getEmailVerified())
                .familyName(user.getFamilyName())
                .gender(user.getGender())
                .givenName(user.getGivenName())
                .locale(user.getLocale())
                .middleName(user.getMiddleName())
                .name(user.getName())
                .nickname(user.getNickname())
                .picture(user.getPicture())
                .phoneNumber(user.getPhoneNumber())
                .phoneNumberVerified(user.getPhoneNumberVerified())
                .preferredUsername(user.getPreferredUsername())
                .profile(user.getProfile())
                .subject(user.getSubject())
                .updatedAt(user.getUpdatedAt())
                .website(user.getWebsite())
                .zoneinfo(user.getZoneinfo())

                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getAuthorities().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()))
                .status(user.getStatus())
                .deleted(user.getDeleted())
                .contact(contact)
                .claims(claimsConsumer -> {
                    if (user.getExpand() != null) {
                        claimsConsumer.putAll(user.getExpand());
                    }
                })
                .build();
    }

    public static Map<String, Object> toRegisterMap(AuthUser user, String type, String username, String password, String loginType, String userId) {
        Map<String, Object> expand = new HashMap<>();
        expand.put("snapshotUser", user.isSnapshotUser());
        expand.put("type", type);
        Optional.ofNullable(userId).ifPresent(v -> expand.put("userId", v));
        Optional.ofNullable(user.getUuid()).ifPresent(v -> expand.put("id", v));
        Optional.ofNullable(user.getUsername()).ifPresent(v -> expand.put("username", v));
        Optional.ofNullable(password).ifPresent(v -> expand.put("password", v));
        Optional.ofNullable(user.getNickname()).ifPresent(v -> expand.put("nickname", v));
        Optional.ofNullable(user.getGender()).ifPresent(v -> expand.put("gender", v.name()));
        Optional.ofNullable(user.getLocation()).ifPresent(v -> expand.put("address", v));
        Optional.ofNullable(user.getAvatar()).ifPresent(v -> expand.put("picture", v));
        Optional.ofNullable(user.getBlog()).ifPresent(v -> expand.put("website", v));
        Optional.ofNullable(user.getSource()).ifPresent(v -> expand.put("source", v));

        if (SecurityConstants.OAUTH_FORM_EMAIL_LOGIN_TYPE.equals(loginType)) {
            Optional.ofNullable(username).ifPresent(v -> expand.put("email", v));
        }
        if (SecurityConstants.OAUTH_FORM_PHONE_LOGIN_TYPE.equals(loginType)) {
            Optional.ofNullable(username).ifPresent(v -> expand.put("phoneNumber", v));
        }

        if (user.getToken() != null) {
            AuthToken token = user.getToken();
            Optional.ofNullable(token.getOpenId()).ifPresent(v -> expand.put("openId", v));
            Optional.ofNullable(token.getUnionId()).ifPresent(v -> expand.put("unionId", v));
        }

        return expand;
    }


}
