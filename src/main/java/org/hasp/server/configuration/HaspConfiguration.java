package org.hasp.server.configuration;


import lombok.extern.slf4j.Slf4j;
import org.hasp.server.repository.core.TransferClientRepository;
import org.hasp.server.repository.core.TransferUserRepository;
import org.hasp.server.repository.memory.MemoryTransferClientRepository;
import org.hasp.server.repository.memory.MemoryTransferUserRepository;
import org.hasp.server.repository.remote.RemoteTransferClientRepository;
import org.hasp.server.repository.remote.RemoteTransferUserRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@Configuration(proxyBeanMethods = false)
//@EnableConfigurationProperties(JustAuthProperties.class)
public class HaspConfiguration {


    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(name = "hasp.data.type", havingValue = "memory", matchIfMissing = true)
    public static class MemoryTransferRepositoryConfiguration {
        static {
            log.debug("Hasp Auth Server 使用 Memory 加载数据");
        }

        @Bean
        public TransferClientRepository transferClientRepository(PasswordEncoder passwordEncoder) {
            return new MemoryTransferClientRepository(passwordEncoder);
        }

        @Bean
        public TransferUserRepository transferUserRepository(PasswordEncoder passwordEncoder) {
            return new MemoryTransferUserRepository(passwordEncoder);
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(name = "hasp.data.type", havingValue = "remote", matchIfMissing = true)
    static class RemoteTransferRepositoryConfiguration {
        static {
            log.debug("Hasp Auth Server 使用 Remote 加载数据");
        }

        @Bean
        public TransferClientRepository transferClientRepository() {
            return new RemoteTransferClientRepository();
        }

        @Bean
        public TransferUserRepository transferUserRepository() {
            return new RemoteTransferUserRepository();
        }
    }


}
