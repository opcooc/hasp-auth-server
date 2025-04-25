package org.hasp.server.repository.core;

import org.hasp.server.dto.TransferUser;

import java.util.Map;

public interface TransferUserRepository {

    /**
     * 加载用户信息(手机号或者邮箱自动注册逻辑相关业务系统自己处理)
     */
    TransferUser load(String username, String source);

    /**
     * 注册用户信息(手机号+社交账户，邮箱+社交账户)
     */
    void register(Map<String, Object> map);

    /**
     * 更改用户密码(用于密码的自动升级)
     */
    void updatePassword(String userId, String newPassword);
}
