package org.hasp.server.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthUser;
import org.hasp.server.service.FederatedService;
import org.hasp.server.utils.SecurityConstants;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.UUID;

@Controller
@RequiredArgsConstructor
public class OauthFederatedController {

    private final FederatedService federatedService;

    @Operation(summary = "联合登录跳转", description = "根据source跳转对应的登录页面")
    @Parameters({
            @Parameter(name = "source", description = "登录来源", in = ParameterIn.QUERY),
            @Parameter(name = "bind", description = "是否为绑定操作(true:是，false:否)", in = ParameterIn.QUERY)
    })
    @GetMapping(SecurityConstants.OAUTH_FEDERATED_AUTHORIZE_URI)
    public void authorize(HttpServletRequest request, HttpServletResponse response,
                          @PathVariable("source") String source,
                          @RequestParam(value = "bind", required = false, defaultValue = "false") Boolean bind) throws IOException {
        federatedService.authorize(request, response, source, bind, UUID.randomUUID().toString());
    }

    @Operation(summary = "联合登录回调", description = "需要在第三方系统配置")
    @Parameters({
            @Parameter(name = "source", description = "登录来源", in = ParameterIn.PATH)
    })
    @RequestMapping(value = SecurityConstants.OAUTH_FEDERATED_CALLBACK_URI, method = {RequestMethod.GET, RequestMethod.POST})
    public void callback(HttpServletRequest request, HttpServletResponse response,
                         @PathVariable("source") String source, AuthCallback callback) throws ServletException, IOException {
        federatedService.callback(request, response, source, callback);
    }

    @Operation(summary = "联合登录注册", description = "需要在第三方系统配置")
    @Parameters({
            @Parameter(name = OAuth2ParameterNames.USERNAME, description = "账户", in = ParameterIn.QUERY),
            @Parameter(name = OAuth2ParameterNames.PASSWORD, description = "密码", in = ParameterIn.QUERY),
            @Parameter(name = SecurityConstants.OAUTH_FORM_LOGIN_TYPE_PARAM, description = "登录类型", in = ParameterIn.QUERY)
    })
    @PostMapping(SecurityConstants.OAUTH_FEDERATED_REGISTER_URI)
    public void register(HttpServletRequest request, HttpServletResponse response,
                         @RequestParam(OAuth2ParameterNames.USERNAME) String username,
                         @RequestParam(OAuth2ParameterNames.PASSWORD) String password,
                         @RequestParam(SecurityConstants.OAUTH_FORM_LOGIN_TYPE_PARAM) String loginType,
                         @SessionAttribute(value = SecurityConstants.AUTH_FEDERATED_USER) AuthUser authUser)
            throws ServletException, IOException {
        federatedService.register(request, response, username, password, loginType, authUser);
    }

    @Operation(summary = "联合登录绑定回调页面", description = "系统内置页面")
    @Parameters({
            @Parameter(name = "error", description = "错误信息", in = ParameterIn.QUERY)
    })
    @GetMapping(SecurityConstants.OAUTH_FEDERATED_OUTCOME_PAGE_URI)
    public String outcome(Model model, @RequestParam(required = false) String error) {
        model.addAttribute("error", false);
        if (StringUtils.hasLength(error)) {
            model.addAttribute("error", true);
            model.addAttribute("error_message", error);
        }
        return "outcome";
    }

    @Operation(summary = "撤销联合登录授权", description = "需要第三方系统同时删除关联信息")
    @Parameters({
            @Parameter(name = "source", description = "登录来源", in = ParameterIn.QUERY)
    })
    @DeleteMapping(SecurityConstants.OAUTH_FEDERATED_REVOKE_URI)
    public void revoke(HttpServletRequest request, HttpServletResponse response, @PathVariable("source") String source) {
        federatedService.revoke(request, response, source);
    }

}
