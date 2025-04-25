package org.hasp.server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TransferUser {

    // 标准OIDC声明字段
    private String address;                // 地址(JSON字符串)
    private String birthdate;              // 生日(YYYY-MM-DD)
    private String email;                  // 电子邮箱
    private Boolean emailVerified;         // 邮箱是否已验证
    private String familyName;             // 姓氏
    private String gender;                 // 性别(male/female/other)
    private String givenName;              // 名字
    private String locale;                 // 区域设置(默认zh-CN)
    private String middleName;             // 中间名
    private String name;                   // 全名
    private String nickname;               // 昵称
    private String picture;                // 头像URL
    private String phoneNumber;            // 电话号码
    private Boolean phoneNumberVerified;   // 电话号码是否已验证
    private String preferredUsername;      // 首选用户名
    private String profile;                // 个人资料页URL
    private String subject;                // 主题标识(用户ID)
    private String updatedAt;              // 最后更新时间(ISO8601格式)
    private String website;                // 个人网站
    private String zoneinfo;               // 时区信息(默认Asia/Shanghai)

    // 安全相关字段
    private String password;               // 密码(加密存储)
    private String username;               // 用户名
    private Set<String> authorities;       // 授予的权限集合(例如：ROLE_ADMIN)
    private Integer status;                // 账户状态 过期、锁定、
    private Boolean deleted;               // 账户是否删除

    // 其他字段
    private String source;                 // 账户来源
    private Map<String, Object> expand;    // 其他信息
}
