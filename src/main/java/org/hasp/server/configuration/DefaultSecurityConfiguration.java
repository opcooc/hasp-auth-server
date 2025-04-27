package org.hasp.server.configuration;

import org.hasp.server.event.AuthenticationEventListener;
import org.hasp.server.utils.SecurityConstants;
import org.hasp.server.utils.SecurityUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          SessionRegistry sessionRegistry) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(customizer -> {
            customizer.requestMatchers(
                            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html",
                            "/assets/**",
                            SecurityConstants.OAUTH_FEDERATED_AUTHORIZE_URI,
                            SecurityConstants.OAUTH_FEDERATED_CALLBACK_URI,
                            SecurityConstants.OAUTH_SIGN_UP_PAGE_URI)
                    .permitAll()
                    .anyRequest()
                    .authenticated();
        });

        http.formLogin(customizer -> {
//            customizer.authenticationDetailsSource()
            customizer.permitAll();
            customizer.loginProcessingUrl(SecurityConstants.OAUTH_LOGIN_URI);
            customizer.loginPage(SecurityConstants.OAUTH_SIGN_IN_PAGE_URI);
            customizer.failureUrl(SecurityConstants.OAUTH_SIGN_IN_PAGE_URI);
        });

        http.sessionManagement(customizer -> {
            customizer.sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::changeSessionId);
            customizer.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
            customizer.sessionConcurrency(sessionConcurrency -> {
                sessionConcurrency.maximumSessions(6);
                sessionConcurrency.sessionRegistry(sessionRegistry);
                sessionConcurrency.expiredUrl(SecurityConstants.OAUTH_SIGN_IN_PAGE_URI);
            });
        });

        http.logout(customizer -> {
        });

        http.oauth2ResourceServer(customizer -> {
            customizer.jwt(Customizer.withDefaults());
            customizer.accessDeniedHandler(SecurityUtils::exceptionHandler);
            customizer.authenticationEntryPoint(SecurityUtils::exceptionHandler);
        });

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationEventListener authenticationEventListener(OAuth2AuthorizationService authorizationService) {
        return new AuthenticationEventListener(authorizationService);
    }

}
