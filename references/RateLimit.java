package com.lycosoft.backend.common.annotation;


import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.concurrent.TimeUnit;

/**
 * Rate limiting annotation using token bucket algorithm
 *
 * Usage:
 * @RateLimit(limit = 10, duration = 60, unit = TimeUnit.SECONDS)
 * public void myMethod() { ... }
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {

    /**
     * Maximum number of requests allowed
     */
    int limit() default 100;

    /**
     * Duration for the rate limit window
     */
    long duration() default 60;

    /**
     * Time unit for duration
     */
    TimeUnit unit() default TimeUnit.SECONDS;

    /**
     * Key for rate limiting (SpEL expression supported)
     * Default: Uses IP address
     * Examples: "#userId", "#request.username", "global"
     */
    String key() default "IP";

    /**
     * Error message when rate limit is exceeded
     */
    String message() default "Rate limit exceeded. Please try again later.";
}
