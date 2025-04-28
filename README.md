# HASP Auth Server

## 📚 目录
- [项目简介](#项目简介)
- [技术选型](#技术选型)
- [功能概览](#功能概览)
- [模块划分](#模块划分)
- [接口文档](#接口文档)
    - [获取 Token（密码模式）](#1-获取-token密码模式)
    - [刷新 Token](#2-刷新-token)
    - [获取当前登录用户信息](#3-获取当前登录用户信息)
- [外部用户服务集成说明](#外部用户服务集成说明)
- [部署方式](#部署方式)
- [使用示例](#使用示例)
- [注意事项](#注意事项)
- [版本信息](#版本信息)

---

## 项目简介

HASP Auth Server 是一个基于 Spring Authorization Server 的认证授权服务，支持标准 OAuth2 流程和 JWT 签发，用户信息、客户端信息通过外部 HTTP 服务动态获取，适用于中大型分布式系统的统一认证场景。

---

## 技术选型

- Java 21+
- Spring Boot 3.x
- Spring Authorization Server
- Spring Security 6.x
- JWT（JSON Web Token）
- Redis
- Lombok

---

## 功能概览

- 用户认证与授权
- OAuth2 授权码模式
- JWT 生成与验证
- 支持外部用户服务集成
- Token 自动刷新机制
- 定时轮换本地密钥文件
---

## 模块划分

- 认证模块：登录、登出、刷新 Token
- 用户模块：通过外部 HTTP 获取用户信息

---

## 接口文档

### 1. 获取 Token（密码模式）

- **URL**: `/oauth2/token`
- **方法**: `POST`

**请求参数**:

| 参数          | 类型    | 必填 | 说明               |
|:-------------|:-------|:----|:------------------|
| grant_type   | string | 是  | 固定为 `password`    |
| username     | string | 是  | 用户名              |
| password     | string | 是  | 密码               |
| client_id    | string | 是  | 客户端ID            |
| client_secret| string | 是  | 客户端密钥           |

**响应示例**:

```json
{
  "access_token": "eyJraWQiOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}




http://127.0.0.1:9898/oauth2/authorize?response_type=code&scope=profile%20openid&client_id=demo&redirect_uri=http://127.0.0.1:9527/home&state=8a0781548e7f76ae018e94e450982413
http://127.0.0.1:9898/swagger-ui/index.html