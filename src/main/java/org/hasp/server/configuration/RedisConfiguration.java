package org.hasp.server.configuration;

import io.github.jayrobim.justauth.autoconfigure.JustAuthProperties;
import io.github.jayrobim.justauth.support.cache.RedisStateCache;
import me.zhyd.oauth.cache.AuthStateCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;

@Configuration(proxyBeanMethods = false)
@EnableRedisRepositories("org.hasp.server.repository.redis")
public class RedisConfiguration {

    @Bean
    public RedisTemplate<?, ?> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<byte[], byte[]> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        return redisTemplate;
    }

    @Bean
    public AuthStateCache authStateCache(StringRedisTemplate stringRedisTemplate, JustAuthProperties justAuthProperties) {
        return new RedisStateCache(stringRedisTemplate, justAuthProperties.getCache());
    }

}
