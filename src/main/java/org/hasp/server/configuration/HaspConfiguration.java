package org.hasp.server.configuration;


import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Slf4j
@Configuration
//@EnableConfigurationProperties(JustAuthProperties.class)
public class HaspConfiguration {

    @Configuration
    @Import({TransferRepositoryConfiguration.Memory.class, TransferRepositoryConfiguration.Remote.class})
    protected static class TransferRepositoryImportConfiguration {

    }

}
