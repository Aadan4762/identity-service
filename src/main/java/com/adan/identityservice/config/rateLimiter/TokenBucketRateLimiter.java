package com.adan.identityservice.config.rateLimiter;



import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Component
public class TokenBucketRateLimiter {

    private final RedisTemplate<String, Object> redisTemplate;
    private final RateLimitProperties properties;

    public TokenBucketRateLimiter(RedisTemplate<String, Object> redisTemplate,
                                  RateLimitProperties properties) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
    }

    // Enum for different rate limit types
    public enum RateLimitType {
        AUTH_LOGIN,
        AUTH_REGISTER,
        AUTH_OTP,
        AUTH_GENERAL,
        DEPT_READ,
        DEPT_WRITE
    }

    public boolean tryConsume(String clientIdentifier, RateLimitType type, int tokensRequested) {
        RateLimitConfig config = getRateLimitConfig(type);
        String bucketKey = properties.getKeyPrefix() + type.name().toLowerCase() + ":" + clientIdentifier;
        long currentTime = System.currentTimeMillis();

        String luaScript = """
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refillRate = tonumber(ARGV[2])
            local tokensRequested = tonumber(ARGV[3])
            local currentTime = tonumber(ARGV[4])
            local windowSize = tonumber(ARGV[5])
            
            -- Get current bucket state
            local bucket = redis.call('HMGET', key, 'tokens', 'lastRefill')
            local tokens = tonumber(bucket[1]) or capacity
            local lastRefill = tonumber(bucket[2]) or currentTime
            
            -- Calculate tokens to add based on time elapsed (per minute refill)
            local timeElapsed = (currentTime - lastRefill) / 1000 / 60
            local tokensToAdd = math.floor(timeElapsed * refillRate)
            
            -- Update tokens (don't exceed capacity)
            tokens = math.min(capacity, tokens + tokensToAdd)
            
            -- Check if we can consume the requested tokens
            if tokens >= tokensRequested then
                tokens = tokens - tokensRequested
                
                -- Update bucket state
                redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', currentTime)
                redis.call('EXPIRE', key, windowSize)
                
                return {1, tokens} -- Success, remaining tokens
            else
                -- Update last refill time even if request is denied
                redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', currentTime)
                redis.call('EXPIRE', key, windowSize)
                
                return {0, tokens} -- Failure, remaining tokens
            end
            """;

        DefaultRedisScript<List> script = new DefaultRedisScript<>();
        script.setScriptText(luaScript);
        script.setResultType(List.class);

        List<Object> result = redisTemplate.execute(
                script,
                Collections.singletonList(bucketKey),
                config.getCapacity(),
                config.getRefillRate(),
                tokensRequested,
                currentTime,
                properties.getWindowSizeInSeconds()
        );

        return result != null && "1".equals(result.get(0).toString());
    }

    public TokenBucketInfo getBucketInfo(String clientIdentifier, RateLimitType type) {
        RateLimitConfig config = getRateLimitConfig(type);
        String bucketKey = properties.getKeyPrefix() + type.name().toLowerCase() + ":" + clientIdentifier;

        List<Object> bucket = redisTemplate.opsForHash().multiGet(bucketKey,
                Arrays.asList("tokens", "lastRefill"));

        Integer tokens = bucket.get(0) != null ? (Integer) bucket.get(0) : config.getCapacity();
        Long lastRefill = bucket.get(1) != null ? (Long) bucket.get(1) : System.currentTimeMillis();

        return new TokenBucketInfo(tokens, lastRefill, config.getCapacity(), config.getRefillRate());
    }

    private RateLimitConfig getRateLimitConfig(RateLimitType type) {
        return switch (type) {
            case AUTH_LOGIN -> new RateLimitConfig(
                    properties.getAuthEndpoints().getLoginCapacity(),
                    properties.getAuthEndpoints().getLoginRefillRate()
            );
            case AUTH_REGISTER -> new RateLimitConfig(
                    properties.getAuthEndpoints().getRegisterCapacity(),
                    properties.getAuthEndpoints().getRegisterRefillRate()
            );
            case AUTH_OTP -> new RateLimitConfig(
                    properties.getAuthEndpoints().getOtpCapacity(),
                    properties.getAuthEndpoints().getOtpRefillRate()
            );
            case AUTH_GENERAL -> new RateLimitConfig(
                    properties.getAuthEndpoints().getGeneralCapacity(),
                    properties.getAuthEndpoints().getGeneralRefillRate()
            );
            case DEPT_READ -> new RateLimitConfig(
                    properties.getDepartmentEndpoints().getReadCapacity(),
                    properties.getDepartmentEndpoints().getReadRefillRate()
            );
            case DEPT_WRITE -> new RateLimitConfig(
                    properties.getDepartmentEndpoints().getWriteCapacity(),
                    properties.getDepartmentEndpoints().getWriteRefillRate()
            );
        };
    }

    @Data
    @AllArgsConstructor
    private static class RateLimitConfig {
        private int capacity;
        private int refillRate;
    }

    @Data
    @AllArgsConstructor
    public static class TokenBucketInfo {
        private int currentTokens;
        private long lastRefillTime;
        private int capacity;
        private int refillRate;
    }
}