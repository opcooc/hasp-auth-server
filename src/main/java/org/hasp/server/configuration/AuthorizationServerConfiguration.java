package org.hasp.server.configuration;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.hasp.server.support.CustomAuthenticationProvider;
import org.hasp.server.support.CustomOAuth2TokenCustomizers;
import org.hasp.server.support.CustomOidcLogoutHandler;
import org.hasp.server.support.CustomOidcUserInfoMapper;
import org.hasp.server.utils.KeyUtils;
import org.hasp.server.utils.SecurityConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, ApplicationEventPublisher eventPublisher, OAuth2AuthorizationService authorizationService) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        OAuth2AuthorizationServerConfigurer httpConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        httpConfigurer.authorizationEndpoint(customizer -> {
            customizer.consentPage(SecurityConstants.OAUTH_CONSENT_PAGE_URI);
        });

        httpConfigurer.tokenEndpoint(Customizer.withDefaults());

        httpConfigurer.oidc(customizer -> {

            customizer.userInfoEndpoint(userInfo -> {
                userInfo.userInfoMapper(new CustomOidcUserInfoMapper());
            });

            customizer.logoutEndpoint(logout -> {
                OidcLogoutAuthenticationSuccessHandler oidcLogoutSuccessHandler = new OidcLogoutAuthenticationSuccessHandler();
                oidcLogoutSuccessHandler.setLogoutHandler(new CustomOidcLogoutHandler(eventPublisher, authorizationService));
                logout.logoutResponseHandler(oidcLogoutSuccessHandler);
            });

        });

        httpConfigurer.clientAuthentication(Customizer.withDefaults());

        http.securityMatcher(httpConfigurer.getEndpointsMatcher());

        http.with(httpConfigurer, Customizer.withDefaults());

        http.authorizeHttpRequests(customizer -> {
            customizer.anyRequest().authenticated();
        });

        http.exceptionHandling(customizer -> {
            customizer.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint(SecurityConstants.OAUTH_SIGN_IN_PAGE_URI),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            );
        });

        http.oauth2ResourceServer(customizer -> {
            customizer.jwt(Customizer.withDefaults());
        });

        return http.build();
    }

    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(UserDetailsService userDetailsService,
                                                                     PasswordEncoder passwordEncoder,
                                                                     UserDetailsPasswordService userDetailsPasswordService) {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder, userDetailsPasswordService);
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return CustomOAuth2TokenCustomizers.jwtCustomizer();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(@Value("${hasp.cert.dir}") String dir) {
        return (jwkSelector, securityContext) -> {
            try {
                String kid = KeyUtils.loadCurrentKid(dir, "");
                PublicKey publicKey = KeyUtils.loadCurrentPublicKey(dir, "");
                PrivateKey privateKey = KeyUtils.loadCurrentPrivateKey(dir, "");
                RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey).privateKey((RSAPrivateKey) privateKey).keyID(kid).build();
                return jwkSelector.select(new JWKSet(rsaKey));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

}
