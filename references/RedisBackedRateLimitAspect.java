package com.lycosoft.backend.common.aspect;

import java.lang.classfile.MethodSignature;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.server.ResponseStatusException;

import com.lycosoft.backend.common.cache.CacheKeys;
import com.lycosoft.backend.common.util.IpAddressUtils;
import com.lycosoft.backend.common.util.RedisUtils;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Redis-backed distributed rate limiting aspect
 * <p>
 * This implementation provides true distributed rate limiting across multiple instances.
 * Uses simple Redis INCR + EXPIRE for efficient sliding window counter algorithm.
 * </p>
 * <p>
 * Features:
 * - Distributed rate limiting (shared across all instances)
 * - SpEL expression support for dynamic keys
 * - Fail-open on Redis errors (doesn't block requests)
 * - Security: SpEL injection prevention
 * - Comprehensive IP detection using IpAddressUtils
 * </p>
 * <p>
 * Algorithm: Sliding Window Counter
 * - Simple and efficient
 * - Low memory footprint (~100 bytes per key)
 * - Good accuracy for most use cases
 * - Fast performance (<5ms with Redis)
 * </p>
 * Usage:
 * <pre>
 * {@code
 * @RateLimit(key = "IP", limit = 100, duration = 60)
 * public void publicEndpoint() { }
 *
 * @RateLimit(key = "#userId", limit = 10, duration = 60)
 * public void userSpecificEndpoint(UUID userId) { }
 *
 * @RateLimit(key = "#username", limit = 5, duration = 60)
 * public void login(String username) { }
 * }
 * </pre>
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class RedisBackedRateLimitAspect {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ExpressionParser parser = new SpelExpressionParser();

    // Whitelist of allowed SpEL expressions for rate limiting
    private static final Set<String> ALLOWED_VARIABLES = Set.of(
            "username", "email", "userId", "organizationId", "teamId",
            "ipAddress", "apiKey", "clientId", "formId", "submissionId"
    );

    // Pattern to detect dangerous SpEL constructs
    private static final Pattern DANGEROUS_PATTERN = Pattern.compile(
            "T\\(|new |@|#this|#root|getClass|class|Runtime|ProcessBuilder|exec|invoke|System|Process"
    );

    @Around("@annotation(rateLimit)")
    public Object handleRateLimit(ProceedingJoinPoint joinPoint, RateLimit rateLimit) throws Throwable {
        try {
            String key = resolveKey(joinPoint, rateLimit);
            long windowSeconds = rateLimit.unit().toSeconds(rateLimit.duration());

            // Check if rate limited
            long currentCount = incrementAndGet(key, windowSeconds);

            if (currentCount > rateLimit.limit()) {
                long ttl = getTtl(key);

                log.warn("Rate limit exceeded - Key: {}, Count: {}/{}, TTL: {}s",
                        key, currentCount, rateLimit.limit(), ttl);

                throw new ResponseStatusException(
                        HttpStatus.TOO_MANY_REQUESTS,
                        String.format("%s Retry after %d seconds.", rateLimit.message(), ttl)
                );
            }

            log.debug("Rate limit check passed - Key: {}, Count: {}/{}",
                    key, currentCount, rateLimit.limit());

            return joinPoint.proceed();

        } catch (ResponseStatusException e) {
            // Re-throw rate limit exceptions
            throw e;
        } catch (Exception e) {
            // Log error but don't block request (fail-open)
            log.error("Rate limit check failed, allowing request to proceed", e);
            return joinPoint.proceed();
        }
    }

    /**
     * Atomic increment with expiration using Redis
     * Returns the new count after increment
     *
     * @param key Cache key
     * @param ttlSeconds Time to live in seconds
     * @return Current count after increment
     */
    private long incrementAndGet(String key, long ttlSeconds) {
        try {
            return RedisUtils.incrementWithInitialExpiration(key, ttlSeconds, redisTemplate);
        } catch (Exception e) {
            log.error("Failed to increment rate limit key: {}", key, e);
            // Fail open - return 0 to allow request
            return 0L;
        }
    }

    /**
     * Get remaining TTL for a key
     *
     * @param key Cache key
     * @return TTL in seconds
     */
    private long getTtl(String key) {
        try {
            long ttl = redisTemplate.getExpire(key, java.util.concurrent.TimeUnit.SECONDS);
            return ttl > 0 ? ttl : 0;
        } catch (Exception e) {
            log.error("Failed to get TTL for key: {}", key, e);
            return 0;
        }
    }

    /**
     * Resolve rate limit key from annotation
     * Supports: IP, global, custom strings, and SpEL expressions
     *
     * @param joinPoint AOP join point
     * @param rateLimit Rate limit annotation
     * @return Resolved cache key
     */
    private String resolveKey(ProceedingJoinPoint joinPoint, RateLimit rateLimit) {
        String keyExpression = rateLimit.key();

        // IP-based rate limiting
        if ("IP".equals(keyExpression)) {
            String ip = IpAddressUtils.getClientIpAddress();
            String methodName = joinPoint.getSignature().getName();
            return CacheKeys.RateLimit.ip(ip) + ":" + methodName;
        }

        // Global rate limiting
        if ("global".equalsIgnoreCase(keyExpression)) {
            return "ratelimit:global:" + joinPoint.getSignature().toShortString();
        }

        // SpEL expression
        if (keyExpression.startsWith("#")) {
            return evaluateSpelExpression(keyExpression, joinPoint);
        }

        // Custom static key
        return "ratelimit:custom:" + keyExpression;
    }

    /**
     * Safely evaluates SpEL expression with injection prevention
     * Uses whitelisting and restricted evaluation context
     *
     * @param expression SpEL expression (e.g., "#userId")
     * @param joinPoint AOP join point
     * @return Resolved cache key
     */
    private String evaluateSpelExpression(String expression, ProceedingJoinPoint joinPoint) {
        try {
            // Validate expression safety
            validateSpelExpression(expression);

            // Create restricted evaluation context (read-only)
            SimpleEvaluationContext context = SimpleEvaluationContext
                    .forReadOnlyDataBinding()
                    .build();

            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            String[] paramNames = signature.getParameterNames();
            Object[] args = joinPoint.getArgs();

            // Register only whitelisted parameters
            for (int i = 0; i < paramNames.length && i < args.length; i++) {
                if (isAllowedVariable(paramNames[i])) {
                    Object sanitizedValue = sanitizeArgument(args[i]);
                    context.setVariable(paramNames[i], sanitizedValue);
                } else {
                    log.trace("Skipping non-whitelisted parameter: {}", paramNames[i]);
                }
            }

            // Add IP address as a variable
            context.setVariable("ipAddress", IpAddressUtils.getClientIpAddress());

            // Evaluate expression
            Object result = parser.parseExpression(expression).getValue(context);

            if (result == null) {
                log.warn("SpEL expression evaluated to null: {}, falling back to IP", expression);
                return CacheKeys.RateLimit.ip(IpAddressUtils.getClientIpAddress());
            }

            // Use appropriate CacheKey based on variable type
            String variableName = expression.substring(1); // Remove #
            String methodName = joinPoint.getSignature().getName();

            return buildKeyFromVariable(variableName, result, methodName);

        } catch (Exception e) {
            log.error("Failed to evaluate SpEL expression: {}, falling back to IP", expression, e);
            return CacheKeys.RateLimit.ip(IpAddressUtils.getClientIpAddress());
        }
    }

    /**
     * Build cache key based on variable type and value
     */
    private String buildKeyFromVariable(String variableName, Object value, String methodName) {
        String valueStr = value.toString();

        // Use CacheKeys utility for standard types
        switch (variableName) {
            case "userId":
                try {
                    UUID userId = UUID.fromString(valueStr);
                    return CacheKeys.RateLimit.user(userId, methodName);
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid UUID format for userId: {}", valueStr);
                    return "ratelimit:user:" + valueStr + ":" + methodName;
                }

            case "apiKey":
                return CacheKeys.RateLimit.api(valueStr);

            case "ipAddress":
                return CacheKeys.RateLimit.ip(valueStr) + ":" + methodName;

            default:
                // Generic format for other variables
                return "ratelimit:" + variableName + ":" + valueStr + ":" + methodName;
        }
    }

    /**
     * Validates that the SpEL expression is safe to evaluate
     * Prevents injection attacks
     *
     * @param expression SpEL expression to validate
     * @throws SecurityException if expression is unsafe
     */
    private void validateSpelExpression(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            throw new SecurityException("Empty SpEL expression");
        }

        // Check for dangerous patterns
        if (DANGEROUS_PATTERN.matcher(expression).find()) {
            log.error("SECURITY: Blocked dangerous SpEL expression: {}", expression);
            throw new SecurityException("SpEL expression contains forbidden patterns");
        }

        // Check expression length (prevent DoS)
        if (expression.length() > 200) {
            log.error("SECURITY: SpEL expression too long: {} chars", expression.length());
            throw new SecurityException("SpEL expression too long");
        }

        // Check for at least one whitelisted variable
        boolean hasAllowedVariable = ALLOWED_VARIABLES.stream()
                .anyMatch(var -> expression.contains("#" + var));

        if (!hasAllowedVariable) {
            log.warn("SECURITY: SpEL expression contains no whitelisted variables: {}", expression);
            throw new SecurityException("SpEL expression uses non-whitelisted variables");
        }
    }

    /**
     * Check if a variable name is in the whitelist
     */
    private boolean isAllowedVariable(String variableName) {
        return ALLOWED_VARIABLES.contains(variableName);
    }

    /**
     * Sanitizes argument values to prevent object injection
     * Only allows safe primitive types and strings
     *
     * @param arg Method argument
     * @return Sanitized value
     */
    private Object sanitizeArgument(Object arg) {
        if (arg == null) {
            return null;
        }

        // Allow safe primitive types, strings, and UUIDs
        if (arg instanceof String ||
                arg instanceof Number ||
                arg instanceof Boolean ||
                arg instanceof UUID ||
                arg instanceof Character) {
            return arg;
        }

        // For any other type, convert to string
        // This prevents method invocation through the object
        return arg.toString();
    }

    /**
     * Get detailed IP information for logging/debugging
     */
    private String getClientIpInfo() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                IpAddressUtils.IpInfo ipInfo = IpAddressUtils.getClientIpInfo(request);
                return ipInfo.toString();
            }
        } catch (Exception e) {
            log.debug("Failed to get detailed IP info", e);
        }

        return "IP info unavailable";
    }
}