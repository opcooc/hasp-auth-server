package org.hasp.server.utils;

public class SecurityConstants {
    public static final String SECURITY_REQUIREMENT = "bearer_auth";
    public static final String AUTH_FEDERATED_USER = "HASP_AUTH_FEDERATED_USER";

    public static final String OAUTH_LOGIN_URI = "/oauth2/login";
    public static final String OAUTH_SIGN_IN_PAGE_URI = "/oauth2/sign_in";
    public static final String OAUTH_SIGN_UP_PAGE_URI = "/oauth2/sign_up";
    public static final String OAUTH_CONSENT_PAGE_URI = "/oauth2/consent";

    public static final String OAUTH_FEDERATED_AUTHORIZE_URI = "/oauth2/federated/authorize/{source}";
    public static final String OAUTH_FEDERATED_REVOKE_URI = "/oauth2/federated/revoke/{source}";
    public static final String OAUTH_FEDERATED_CALLBACK_URI = "/oauth2/federated/callback/{source}";
    public static final String OAUTH_FEDERATED_REGISTER_URI = "/oauth2/federated/register";
    public static final String OAUTH_FEDERATED_OUTCOME_PAGE_URI = "/oauth2/federated/outcome";

    public static final String OAUTH_FORM_LOGIN_TYPE_PARAM = "login_type";
    public static final String OAUTH_FORM_USERNAME_LOGIN_TYPE = "username";
    public static final String OAUTH_FORM_EMAIL_LOGIN_TYPE = "email";
    public static final String OAUTH_FORM_PHONE_LOGIN_TYPE = "phone";

}
