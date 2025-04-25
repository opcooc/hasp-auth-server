package org.hasp.server.configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "Hasp Auth Server API",
                version = "1.0",
                description = "Hasp Auth Server 提供安全的认证和授权服务"
        )
)
public class SwaggerConfiguration {
}