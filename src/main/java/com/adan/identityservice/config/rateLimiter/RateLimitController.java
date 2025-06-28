package com.adan.identityservice.config.rateLimiter;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin/rate-limit")
@PreAuthorize("hasAuthority('SUPER_ADMIN')")
public class RateLimitController {

    private final TokenBucketRateLimiter rateLimiter;

    public RateLimitController(TokenBucketRateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getRateLimitStatus(
            HttpServletRequest request,
            @RequestParam(required = false) String clientIp) {

        if (clientIp == null) {
            clientIp = getRealClientIpAddress(request);
        }

        Map<String, Object> status = new HashMap<>();

        for (TokenBucketRateLimiter.RateLimitType type : TokenBucketRateLimiter.RateLimitType.values()) {
            TokenBucketRateLimiter.TokenBucketInfo info = rateLimiter.getBucketInfo(clientIp, type);
            status.put(type.name(), info);
        }

        status.put("clientIp", clientIp);
        return ResponseEntity.ok(status);
    }

    @GetMapping("/status/{rateLimitType}")
    public ResponseEntity<TokenBucketRateLimiter.TokenBucketInfo> getSpecificRateLimitStatus(
            HttpServletRequest request,
            @PathVariable String rateLimitType,
            @RequestParam(required = false) String clientIp) {

        if (clientIp == null) {
            clientIp = getRealClientIpAddress(request);
        }

        try {
            TokenBucketRateLimiter.RateLimitType type = TokenBucketRateLimiter.RateLimitType.valueOf(rateLimitType.toUpperCase());
            TokenBucketRateLimiter.TokenBucketInfo info = rateLimiter.getBucketInfo(clientIp, type);
            return ResponseEntity.ok(info);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    private String getRealClientIpAddress(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For", "X-Real-IP", "X-Client-IP"
        };

        for (String headerName : headerNames) {
            String ip = request.getHeader(headerName);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }

        return request.getRemoteAddr();
    }
}
