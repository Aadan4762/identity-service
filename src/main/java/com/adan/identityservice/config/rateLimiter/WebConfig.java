package com.adan.identityservice.config.rateLimiter;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private RateLimitInterceptor rateLimitInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitInterceptor)
                .addPathPatterns("/auth/**", "/api/v2/department/**")
                .excludePathPatterns(
                        "/auth/validate", // Exclude token validation from rate limiting
                        "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**"
                );
    }
}