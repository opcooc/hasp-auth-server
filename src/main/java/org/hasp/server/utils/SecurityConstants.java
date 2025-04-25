package org.hasp.server.utils;

public class SecurityConstants {
    public static final String SECURITY_REQUIREMENT = "bearer_auth";
    public static final String AUTH_FEDERATED_USER = "HASP_AUTH_FEDERATED_USER";

    public static final String OAUTH_LOGIN_URI = "/oauth/login";
    public static final String OAUTH_SIGN_IN_PAGE_URI = "/oauth/sign_in";
    public static final String OAUTH_SIGN_UP_PAGE_URI = "/oauth/sign_up";
    public static final String OAUTH_CONSENT_PAGE_URI = "/oauth/consent";

    public static final String OAUTH_EXTERNAL_AUTHORIZE_URI = "/oauth/external/authorize";
    public static final String OAUTH_EXTERNAL_REVOKE_URI = "/oauth/external/revoke";
    public static final String OAUTH_EXTERNAL_CALLBACK_URI = "/oauth/external/callback/{source}";
    public static final String OAUTH_EXTERNAL_REGISTER_URI = "/oauth/external/register";
    public static final String OAUTH_EXTERNAL_OUTCOME_PAGE_URI = "/oauth/external/outcome";

    public static final String OAUTH_FORM_LOGIN_TYPE_PARAM = "login_type";
    public static final String OAUTH_FORM_USERNAME_LOGIN_TYPE = "username";
    public static final String OAUTH_FORM_EMAIL_LOGIN_TYPE = "email";
    public static final String OAUTH_FORM_PHONE_LOGIN_TYPE = "phone";

}
