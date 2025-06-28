package com.adan.identityservice.config.rateLimiter;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "rate-limit")
@Data
public class RateLimitProperties {
    private AuthEndpoints authEndpoints = new AuthEndpoints();
    private DepartmentEndpoints departmentEndpoints = new DepartmentEndpoints();
    private String keyPrefix = "rate_limit:";
    private long windowSizeInSeconds = 300; // 5 minutes default

    @Data
    public static class AuthEndpoints {
        private int loginCapacity = 5;           // 5 login attempts per window
        private int loginRefillRate = 1;         // 1 token per minute
        private int registerCapacity = 3;        // 3 registrations per window
        private int registerRefillRate = 1;      // 1 token per minute
        private int otpCapacity = 10;            // 10 OTP requests per window
        private int otpRefillRate = 2;           // 2 tokens per minute
        private int generalCapacity = 50;        // General auth operations
        private int generalRefillRate = 10;      // 10 tokens per minute
    }

    @Data
    public static class DepartmentEndpoints {
        private int readCapacity = 100;          // 100 read operations per window
        private int readRefillRate = 20;         // 20 tokens per minute
        private int writeCapacity = 20;          // 20 write operations per window
        private int writeRefillRate = 4;         // 4 tokens per minute
    }
}