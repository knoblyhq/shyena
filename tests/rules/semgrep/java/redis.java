package com.example.demo;

import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

public class RedisConfig {

    @Bean
    RedisTemplate<String, Object> defaultTemplate(RedisConnectionFactory cf) {
        // ruleid: shyena.java.redis-jdk-serialization
        RedisTemplate<String, Object> t = new RedisTemplate<>();
        t.setConnectionFactory(cf);
        t.setKeySerializer(new StringRedisSerializer());
        return t;
    }

    @Bean
    RedisTemplate<String, Object> jsonTemplate(RedisConnectionFactory cf) {
        // ok: shyena.java.redis-jdk-serialization
        RedisTemplate<String, Object> t = new RedisTemplate<>();
        t.setConnectionFactory(cf);
        t.setKeySerializer(new StringRedisSerializer());
        t.setValueSerializer(new StringRedisSerializer());
        return t;
    }

    @Bean
    RedisTemplate<String, Object> explicitJdk(RedisConnectionFactory cf) {
        RedisTemplate<String, Object> t = new RedisTemplate<String, Object>();
        // ruleid: shyena.java.redis-jdk-serialization
        t.setDefaultSerializer(new JdkSerializationRedisSerializer());
        return t;
    }

    @Bean
    RedisCacheConfiguration defaultCache() {
        // ruleid: shyena.java.redis-jdk-serialization
        return RedisCacheConfiguration.defaultCacheConfig().entryTtl(Duration.ofMinutes(10));
    }

    @Bean
    RedisCacheConfiguration stringCache() {
        // ok: shyena.java.redis-jdk-serialization
        return RedisCacheConfiguration.defaultCacheConfig()
            .entryTtl(Duration.ofMinutes(10))
            .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(new StringRedisSerializer()));
    }
}
