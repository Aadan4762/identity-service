package com.adan.identityservice.config.rateLimiter;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class RateLimitInterceptor implements HandlerInterceptor {

    private final TokenBucketRateLimiter rateLimiter;
    private final ObjectMapper objectMapper;

    public RateLimitInterceptor(TokenBucketRateLimiter rateLimiter, ObjectMapper objectMapper) {
        this.rateLimiter = rateLimiter;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws Exception {

        String clientIp = getRealClientIpAddress(request);
        String requestPath = request.getRequestURI();
        String method = request.getMethod();

        // Determine rate limit type based on endpoint
        TokenBucketRateLimiter.RateLimitType rateLimitType = determineRateLimitType(requestPath, method);

        if (rateLimitType == null) {
            return true; // No rate limiting for this endpoint
        }

        // Try to consume a token
        boolean allowed = rateLimiter.tryConsume(clientIp, rateLimitType, 1);

        if (!allowed) {
            handleRateLimitExceeded(response, clientIp, rateLimitType);
            return false;
        }

        // Add rate limit headers to successful requests
        addRateLimitHeaders(response, clientIp, rateLimitType);
        return true;
    }

    private TokenBucketRateLimiter.RateLimitType determineRateLimitType(String path, String method) {
        // Auth endpoints
        if (path.startsWith("/auth/")) {
            if (path.contains("/login")) {
                return TokenBucketRateLimiter.RateLimitType.AUTH_LOGIN;
            } else if (path.contains("/register")) {
                return TokenBucketRateLimiter.RateLimitType.AUTH_REGISTER;
            } else if (path.contains("/otp") || path.contains("/resend-otp")) {
                return TokenBucketRateLimiter.RateLimitType.AUTH_OTP;
            } else {
                return TokenBucketRateLimiter.RateLimitType.AUTH_GENERAL;
            }
        }

        // Department endpoints
        if (path.startsWith("/api/v2/department/")) {
            if ("GET".equalsIgnoreCase(method)) {
                return TokenBucketRateLimiter.RateLimitType.DEPT_READ;
            } else if ("POST".equalsIgnoreCase(method) ||
                    "PUT".equalsIgnoreCase(method) ||
                    "DELETE".equalsIgnoreCase(method)) {
                return TokenBucketRateLimiter.RateLimitType.DEPT_WRITE;
            }
        }

        return null; // No rate limiting
    }

    private void handleRateLimitExceeded(HttpServletResponse response, String clientIp,
                                         TokenBucketRateLimiter.RateLimitType rateLimitType) throws Exception {

        TokenBucketRateLimiter.TokenBucketInfo bucketInfo = rateLimiter.getBucketInfo(clientIp, rateLimitType);

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Add rate limit headers
        response.setHeader("X-RateLimit-Limit", String.valueOf(bucketInfo.getCapacity()));
        response.setHeader("X-RateLimit-Remaining", "0");
        response.setHeader("X-RateLimit-Reset", String.valueOf(bucketInfo.getLastRefillTime() + 300000)); // 5 minutes
        response.setHeader("X-RateLimit-Type", rateLimitType.name());

        // Response body
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", "Rate limit exceeded");
        errorResponse.put("message", String.format("Too many %s requests from IP: %s",
                rateLimitType.name().toLowerCase().replace("_", " "), clientIp));
        errorResponse.put("rateLimitType", rateLimitType.name());
        errorResponse.put("retryAfter", "300 seconds");
        errorResponse.put("currentTokens", bucketInfo.getCurrentTokens());

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));

        log.warn("Rate limit exceeded for IP: {} on endpoint type: {}", clientIp, rateLimitType);
    }

    private void addRateLimitHeaders(HttpServletResponse response, String clientIp,
                                     TokenBucketRateLimiter.RateLimitType rateLimitType) {
        TokenBucketRateLimiter.TokenBucketInfo bucketInfo = rateLimiter.getBucketInfo(clientIp, rateLimitType);
        response.setHeader("X-RateLimit-Limit", String.valueOf(bucketInfo.getCapacity()));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(bucketInfo.getCurrentTokens()));
        response.setHeader("X-RateLimit-Type", rateLimitType.name());
    }

    private String getRealClientIpAddress(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
                "CF-Connecting-IP", "True-Client-IP", "X-Cluster-Client-IP"
        };

        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }

        return request.getRemoteAddr();
    }
}
