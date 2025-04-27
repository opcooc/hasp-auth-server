package org.hasp.server.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import lombok.RequiredArgsConstructor;
import org.hasp.server.dto.core.BasicScope;
import org.hasp.server.utils.SecurityConstants;
import org.hasp.server.utils.SecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashSet;
import java.util.Set;

@Controller
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class OauthController {

    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationServerSettings authorizationServerSettings;

    @Operation(summary = "登录页面", description = "系统内置页面")
    @GetMapping(SecurityConstants.OAUTH_SIGN_IN_PAGE_URI)
    public String signIn() {
        return "sign_in";
    }

    @Operation(summary = "注册页面", description = "系统内置页面")
    @GetMapping(SecurityConstants.OAUTH_SIGN_UP_PAGE_URI)
    public String signUp() {
        return "sign_up";
    }

    @Operation(summary = "OAuth授权页面", description = "系统内置页面")
    @Parameters({
            @Parameter(name = OAuth2ParameterNames.CLIENT_ID, description = "客户端ID", in = ParameterIn.QUERY),
            @Parameter(name = OAuth2ParameterNames.SCOPE, description = "客户端SCOPE", in = ParameterIn.QUERY),
            @Parameter(name = OAuth2ParameterNames.STATE, description = "请求STATE", in = ParameterIn.QUERY),
            @Parameter(name = OAuth2ParameterNames.USER_CODE, description = "请求USER_CODE", in = ParameterIn.QUERY)
    })
    @GetMapping(value = SecurityConstants.OAUTH_CONSENT_PAGE_URI)
    public String consent(Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode) {

        Set<BasicScope> scopeWithDescriptions = new HashSet<>();
        RegisteredClient client = this.registeredClientRepository.findByClientId(clientId);

        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (OidcScopes.OPENID.equals(requestedScope)) {
                continue;
            }
            BasicScope basicScope = BasicScope.fromScope(requestedScope);
            if (basicScope == null) {
                throw new RuntimeException("basicScope is null");
            }
            scopeWithDescriptions.add(basicScope);
        }

        model.addAttribute("user", SecurityUtils.getUser().getClaims());
        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", client.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopeWithDescriptions);
        model.addAttribute("userCode", userCode);

        String requestUri = StringUtils.hasText(userCode)
                ? authorizationServerSettings.getDeviceVerificationEndpoint()
                : authorizationServerSettings.getAuthorizationEndpoint();
        model.addAttribute("requestURI", requestUri);

        return "consent";
    }

}
