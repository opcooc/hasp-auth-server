package org.hasp.server.repository.memory;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.hasp.server.dto.TransferUser;
import org.hasp.server.repository.core.TransferUserRepository;
import org.hasp.server.utils.SecurityConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class MemoryTransferUserRepository implements TransferUserRepository {

    private final PasswordEncoder passwordEncoder;
    private final static Map<String, TransferUser> USER_MAP = new HashMap<>();

    static {
        TransferUser adminUser = TransferUser.builder()
                .subject("MEMORY_TRANSFER_USER_ID")
                .nickname("MEMORY_TRANSFER_NICKNAME")
                .username("admin")
                .source(SecurityConstants.OAUTH_FORM_USERNAME_LOGIN_TYPE)
                .password("{bcrypt}$2a$10$B0MXaXhil1.2Z.ROCWMQiuZ1MSVcqF.Hmt9/z1ieFgEhtS9XZsa0y") // password
                .authorities(Collections.singleton("MEMORY_TRANSFER_ROLE_USER"))
                .build();

        USER_MAP.put("admin" + SecurityConstants.OAUTH_FORM_USERNAME_LOGIN_TYPE, adminUser);
        USER_MAP.put(adminUser.getSubject(), adminUser);
    }

    @Override
    public TransferUser load(String username, String source) {
        TransferUser user = USER_MAP.get(username + source);
        if (user == null && StringUtils.equalsAny(source,
                SecurityConstants.OAUTH_FORM_PHONE_LOGIN_TYPE, SecurityConstants.OAUTH_FORM_EMAIL_LOGIN_TYPE)) {
            TransferUser memoryTransferUser = TransferUser.builder()
                    .subject(UUID.randomUUID().toString().replace("-", ""))
                    .username(username)
                    .source(source)
                    .email(StringUtils.equalsAny(source, SecurityConstants.OAUTH_FORM_PHONE_LOGIN_TYPE) ? username : null)
                    .emailVerified(true)
                    .phoneNumber(StringUtils.equalsAny(source, SecurityConstants.OAUTH_FORM_EMAIL_LOGIN_TYPE) ? username : null)
                    .phoneNumberVerified(true)
                    .authorities(Collections.singleton("MEMORY_TRANSFER_ROLE_USER"))
                    .build();
            USER_MAP.put(username + source, memoryTransferUser);
            USER_MAP.put(memoryTransferUser.getSubject(), memoryTransferUser);
            return memoryTransferUser;
        }
        return user;
    }

    @Override
    public void register(Map<String, Object> map) {
        String type = (String) map.get("type");
        if (StringUtils.equals(type, "bind")) {
            String id = (String) map.get("id");
            String source = (String) map.get("source");
            String nickname = (String) map.get("nickname");
            String userId = (String) map.get("userId");

            TransferUser user = USER_MAP.get(id + source);
            if (user != null) {
                if (!StringUtils.equals(user.getSubject(), userId)) {
                    throw new InternalAuthenticationServiceException("用户[" + nickname + "]已被其他账户绑定");
                }
                return;
            }
            user = USER_MAP.get(userId);
            if (user == null) {
                throw new InternalAuthenticationServiceException("用户不存在");
            }
            USER_MAP.put(id + source, user);
        }
        if (StringUtils.equals(type, "register")) {
            String id = (String) map.get("id");
            String source = (String) map.get("source");
            String nickname = (String) map.get("nickname");
            String email = (String) map.get("email");
            String phoneNumber = (String) map.get("phoneNumber");
            String username = (String) map.get("username");
            String gender = (String) map.get("gender");
            String picture = (String) map.get("picture");

            TransferUser user = USER_MAP.get(id + source);
            if (user != null) {
                throw new InternalAuthenticationServiceException("用户[" + nickname + "]已存在");
            }

            if (email != null) {
                user = USER_MAP.get(email + SecurityConstants.OAUTH_FORM_EMAIL_LOGIN_TYPE);
            }

            if (phoneNumber != null) {
                user = USER_MAP.get(phoneNumber + SecurityConstants.OAUTH_FORM_PHONE_LOGIN_TYPE);
            }

            if (user == null) {
                user = TransferUser.builder()
                        .subject(UUID.randomUUID().toString().replace("-", ""))
                        .username(username)
                        .source(SecurityConstants.OAUTH_FORM_USERNAME_LOGIN_TYPE)
                        .email(email)
                        .emailVerified(true)
                        .phoneNumber(phoneNumber)
                        .phoneNumberVerified(true)
                        .gender(gender)
                        .picture(picture)
                        .authorities(Collections.singleton("MEMORY_TRANSFER_ROLE_USER"))
                        .build();
                if (email != null) {
                    USER_MAP.put(email + SecurityConstants.OAUTH_FORM_EMAIL_LOGIN_TYPE, user);
                }
                if (phoneNumber != null) {
                    USER_MAP.put(phoneNumber + SecurityConstants.OAUTH_FORM_PHONE_LOGIN_TYPE, user);
                }
                USER_MAP.put(user.getSubject(), user);
            }
            USER_MAP.put(id + source, user);
        }
    }

    @Override
    public void updatePassword(String userId, String newPassword) {
        TransferUser user = USER_MAP.get(userId);
        if (user != null) {
            user.setPassword(newPassword);
        }
    }

}
