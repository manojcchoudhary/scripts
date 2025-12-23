package com.lycosoft.backend.common.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.logging.log4j.util.Strings;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * IP Address Utilities
 * Provides comprehensive IP address manipulation and validation
 */
@Slf4j
public class IpAddressUtils {

    /**
     * Utility class for extracting client IP addresses from HTTP requests
     * Handles various proxy headers and CDN configurations
     *
     * Supports:
     * - X-Forwarded-For (most common proxy header)
     * - X-Real-IP (nginx proxy header)
     * - Proxy-Client-IP (Apache proxy)
     * - WL-Proxy-Client-IP (WebLogic proxy)
     * - HTTP_X_FORWARDED_FOR (alternative header format)
     * - HTTP_CLIENT_IP (older proxy header)
     * - CF-Connecting-IP (Cloudflare CDN)
     * - True-Client-IP (Cloudflare Enterprise)
     * - X-Client-IP (various CDNs)
     * - Fastly-Client-IP (Fastly CDN)
     * - X-Cluster-Client-IP (various load balancers)
     * - X-Forwarded (RFC 7239)
     * - Forwarded-For (RFC 7239)
     * - Forwarded (RFC 7239 standard)
     */

    // All known proxy and CDN headers in order of preference
    private static final List<String> IP_HEADERS = Arrays.asList(
            // Cloudflare (highest priority - most trusted)
            "CF-Connecting-IP",
            "True-Client-IP",

            // Standard proxy headers
            "X-Forwarded-For",
            "X-Real-IP",

            // Alternative proxy headers
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",

            // CDN headers
            "X-Client-IP",
            "X-Forwarded",
            "Forwarded-For",
            "Forwarded",
            "X-Cluster-Client-IP",

            // Fastly CDN
            "Fastly-Client-IP",

            // Akamai
            "Akamai-Origin-Hop",

            // Other load balancers
            "X-Azure-ClientIP",
            "X-Azure-SocketIP"
    );

    // IPv4 pattern for validation
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"
    );

    // IPv6 pattern for basic validation
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|" +
                    "^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|" +
                    "^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$"
    );

    // Known private/internal IP ranges to filter out
    private static final List<String> PRIVATE_IP_PREFIXES = Arrays.asList(
            "10.",           // Class A private
            "172.16.",       // Class B private (172.16.0.0 - 172.31.255.255)
            "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.",      // Class C private
            "127.",          // Loopback
            "169.254.",      // Link-local
            "::1",           // IPv6 loopback
            "fc00:",         // IPv6 private
            "fd00:",         // IPv6 private
            "fe80:"          // IPv6 link-local
    );

    private IpAddressUtils() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Convert IP address string to binary representation
     *
     * @param ip IP address string
     * @return Binary representation as byte array
     * @throws UnknownHostException if IP is invalid
     */
    public static byte[] ipToBinary(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);
        return address.getAddress();
    }

    /**
     * Convert binary representation to IP string
     *
     * @param binary Binary IP address
     * @return IP address string
     * @throws UnknownHostException if binary is invalid
     */
    public static String binaryToIp(byte[] binary) throws UnknownHostException {
        InetAddress address = InetAddress.getByAddress(binary);
        return address.getHostAddress();
    }

    /**
     * Get IP version (4 or 6)
     *
     * @param ip IP address string
     * @return 4 for IPv4, 6 for IPv6
     */
    public static int getIpVersion(String ip) {
        return ip.contains(":") ? 6 : 4;
    }

    /**
     * Parse CIDR notation into network components
     *
     * @param cidr CIDR notation (e.g., "192.168.1.0/24")
     * @return CidrBlock with network details
     */
    public static CidrBlock parseCidr(String cidr) {
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid CIDR notation: " + cidr);
        }

        String network = parts[0];
        int prefix = Integer.parseInt(parts[1]);

        try {
            byte[] networkBytes = ipToBinary(network);
            int version = getIpVersion(network);

            // Validate prefix length
            int maxPrefix = version == 4 ? 32 : 128;
            if (prefix < 0 || prefix > maxPrefix) {
                throw new IllegalArgumentException(
                        "Invalid prefix length: " + prefix + " for IPv" + version);
            }

            byte[] startIp = calculateStartIp(networkBytes, prefix, version);
            byte[] endIp = calculateEndIp(networkBytes, prefix, version);

            return new CidrBlock(network, prefix, version, startIp, endIp);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid CIDR notation: " + cidr, e);
        }
    }

    /**
     * Calculate start IP of CIDR block
     *
     * @param network Network address bytes
     * @param prefix Prefix length
     * @param version IP version (4 or 6)
     * @return Start IP as byte array
     */
    private static byte[] calculateStartIp(byte[] network, int prefix, int version) {
        byte[] start = Arrays.copyOf(network, network.length);
        int bits = version == 4 ? 32 : 128;

        // Clear all bits after the prefix
        for (int i = prefix; i < bits; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            start[byteIndex] &= ~(1 << bitIndex);
        }

        return start;
    }

    /**
     * Calculate end IP of CIDR block
     *
     * @param network Network address bytes
     * @param prefix Prefix length
     * @param version IP version (4 or 6)
     * @return End IP as byte array
     */
    private static byte[] calculateEndIp(byte[] network, int prefix, int version) {
        byte[] end = Arrays.copyOf(network, network.length);
        int bits = version == 4 ? 32 : 128;

        // Set all bits after the prefix to 1
        for (int i = prefix; i < bits; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            end[byteIndex] |= (1 << bitIndex);
        }

        return end;
    }

    /**
     * Check if IP is in CIDR range
     *
     * @param ip IP address to check
     * @param startIp Range start IP (binary)
     * @param endIp Range end IP (binary)
     * @return true if IP is in range
     */
    public static boolean isInRange(byte[] ip, byte[] startIp, byte[] endIp) {
        return compareIpAddresses(startIp, ip) <= 0
                && compareIpAddresses(ip, endIp) <= 0;
    }

    /**
     * Compare two IP addresses (binary format)
     *
     * @param ip1 First IP
     * @param ip2 Second IP
     * @return negative if ip1 < ip2, 0 if equal, positive if ip1 > ip2
     */
    public static int compareIpAddresses(byte[] ip1, byte[] ip2) {
        int len = Math.min(ip1.length, ip2.length);
        for (int i = 0; i < len; i++) {
            int byte1 = ip1[i] & 0xFF;
            int byte2 = ip2[i] & 0xFF;
            if (byte1 != byte2) {
                return byte1 - byte2;
            }
        }
        return ip1.length - ip2.length;
    }

    /**
     * Validate IP address format
     *
     * @param ip IP address string
     * @return true if valid
     */
    public static boolean isValidIp(String ip) {
        try {
            InetAddress.getByName(ip);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Check if IP is private (RFC 1918, link-local, loopback, etc.)
     *
     * @param ip IP address string
     * @return true if private
     * @throws UnknownHostException if IP is invalid
     */
    public static boolean isPrivateIp(String ip) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(ip);
        return address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isLoopbackAddress();
    }

    /**
     * Check if IP is in a specific CIDR block
     *
     * @param ip IP address to check
     * @param cidr CIDR block (e.g., "192.168.0.0/16")
     * @return true if IP is in the CIDR block
     */
    public static boolean isInCidr(String ip, String cidr) {
        try {
            byte[] ipBinary = ipToBinary(ip);
            CidrBlock block = parseCidr(cidr);
            return isInRange(ipBinary, block.startIp, block.endIp);
        } catch (Exception e) {
            log.error("Error checking if IP {} is in CIDR {}: {}", ip, cidr, e.getMessage());
            return false;
        }
    }

    /**
     * Get subnet mask for a given prefix length
     *
     * @param prefix Prefix length (e.g., 24)
     * @param version IP version (4 or 6)
     * @return Subnet mask as string
     */
    public static String getSubnetMask(int prefix, int version) {
        if (version != 4) {
            throw new IllegalArgumentException("Subnet mask only applicable to IPv4");
        }

        int mask = 0xffffffff << (32 - prefix);
        return String.format("%d.%d.%d.%d",
                (mask >> 24) & 0xff,
                (mask >> 16) & 0xff,
                (mask >> 8) & 0xff,
                mask & 0xff);
    }

    /**
     * Calculate number of addresses in a CIDR block
     *
     * @param prefix Prefix length
     * @param version IP version
     * @return Number of addresses (capped at Long.MAX_VALUE for IPv6)
     */
    public static long calculateAddressCount(int prefix, int version) {
        if (version == 4) {
            return (long) Math.pow(2, 32 - prefix);
        } else if (version == 6) {
            // For IPv6, we can't represent the full count as a long
            // Return a simplified count for display purposes
            int hostBits = 128 - prefix;
            if (hostBits > 63) {
                return Long.MAX_VALUE; // Too many to represent
            }
            return (long) Math.pow(2, hostBits);
        }
        return 0;
    }

    /**
     * Normalize IP address (expand IPv6, remove leading zeros)
     *
     * @param ip IP address string
     * @return Normalized IP address
     */
    public static String normalizeIp(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            return address.getHostAddress();
        } catch (UnknownHostException e) {
            return ip; // Return original if can't normalize
        }
    }

    /**
     * Check if IP is a bogon (reserved, unallocated, or special-use)
     *
     * @param ip IP address string
     * @return true if bogon
     */
    public static boolean isBogon(String ip) {
        try {
            if (isPrivateIp(ip)) {
                return true;
            }

            InetAddress address = InetAddress.getByName(ip);

            // Check for special addresses
            if (address.isMulticastAddress()
                    || address.isAnyLocalAddress()
                    || address.isLoopbackAddress()
                    || address.isLinkLocalAddress()
                    || address.isSiteLocalAddress()) {
                return true;
            }

            // Check for documentation addresses (IPv4)
            if (getIpVersion(ip) == 4) {
                return isInCidr(ip, "192.0.2.0/24")      // TEST-NET-1
                        || isInCidr(ip, "198.51.100.0/24")  // TEST-NET-2
                        || isInCidr(ip, "203.0.113.0/24")   // TEST-NET-3
                        || isInCidr(ip, "0.0.0.0/8")        // This network
                        || isInCidr(ip, "100.64.0.0/10")    // Shared address space
                        || isInCidr(ip, "192.0.0.0/24")     // IETF protocol assignments
                        || isInCidr(ip, "192.88.99.0/24")   // 6to4 relay anycast
                        || isInCidr(ip, "198.18.0.0/15")    // Benchmarking
                        || isInCidr(ip, "240.0.0.0/4");     // Reserved
            }

            return false;
        } catch (Exception e) {
            log.error("Error checking if IP {} is bogon: {}", ip, e.getMessage());
            return false;
        }
    }

    /**
     * Get IP address type description
     *
     * @param ip IP address string
     * @return Type description (PUBLIC, PRIVATE, LOOPBACK, etc.)
     */
    public static String getIpType(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);

            if (address.isLoopbackAddress()) return "LOOPBACK";
            if (address.isLinkLocalAddress()) return "LINK_LOCAL";
            if (address.isSiteLocalAddress()) return "PRIVATE";
            if (address.isMulticastAddress()) return "MULTICAST";
            if (address.isAnyLocalAddress()) return "ANY_LOCAL";

            if (isBogon(ip)) return "RESERVED";

            return "PUBLIC";
        } catch (UnknownHostException e) {
            return "INVALID";
        }
    }

    /**
     * CIDR Block representation
     */
    @Data
    public static class CidrBlock {
        private final String network;
        private final int prefix;
        private final int version;
        private final byte[] startIp;
        private final byte[] endIp;

        public CidrBlock(String network, int prefix, int version,
                         byte[] startIp, byte[] endIp) {
            this.network = network;
            this.prefix = prefix;
            this.version = version;
            this.startIp = startIp;
            this.endIp = endIp;
        }

        /**
         * Get CIDR notation string
         */
        public String getCidrNotation() {
            return network + "/" + prefix;
        }

        /**
         * Get number of addresses in this block
         */
        public long getAddressCount() {
            return calculateAddressCount(prefix, version);
        }

        /**
         * Get start IP as string
         */
        public String getStartIpString() {
            try {
                return binaryToIp(startIp);
            } catch (UnknownHostException e) {
                return null;
            }
        }

        /**
         * Get end IP as string
         */
        public String getEndIpString() {
            try {
                return binaryToIp(endIp);
            } catch (UnknownHostException e) {
                return null;
            }
        }

        /**
         * Check if an IP is in this block
         */
        public boolean contains(String ip) {
            try {
                byte[] ipBinary = ipToBinary(ip);
                return isInRange(ipBinary, startIp, endIp);
            } catch (UnknownHostException e) {
                return false;
            }
        }

        @Override
        public String toString() {
            return getCidrNotation() + " (" + getAddressCount() + " addresses)";
        }
    }

    /**
     * Extract client IP address from current HTTP request
     * Uses RequestContextHolder to get the current request
     *
     * @return Client IP address, or "unknown" if unable to determine
     */
    public static String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

            if (attributes != null) {
                return getClientIpAddress(attributes.getRequest());
            }
        } catch (Exception e) {
            log.warn("Failed to get client IP address from request context", e);
        }

        return "unknown";
    }

    /**
     * Extract client IP address from HttpServletRequest
     * Checks multiple proxy headers and validates IP format
     *
     * @param request HTTP request
     * @return Client IP address, or "unknown" if unable to determine
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }

        // Try all known headers in order of preference
        for (String header : IP_HEADERS) {
            String ip = extractIpFromHeader(request, header);
            if (!Strings.isBlank(ip)) {
                log.debug("Client IP extracted from header '{}': {}", header, ip);
                return ip;
            }
        }

        // Fallback to remote address
        String remoteAddr = request.getRemoteAddr();
        if (isValidIpAddress(remoteAddr)) {
            log.debug("Client IP from remote address: {}", remoteAddr);
            return remoteAddr;
        }

        log.warn("Unable to determine client IP address");
        return "unknown";
    }

    /**
     * Extract the real client IP from a specific header
     * Handles comma-separated lists (X-Forwarded-For chains)
     *
     * @param request HTTP request
     * @param headerName Header name to check
     * @return Valid IP address or null
     */
    private static String extractIpFromHeader(HttpServletRequest request, String headerName) {
        String headerValue = request.getHeader(headerName);

        if (headerValue == null || headerValue.isEmpty() || "unknown".equalsIgnoreCase(headerValue)) {
            return null;
        }

        // Handle comma-separated list (X-Forwarded-For: client, proxy1, proxy2)
        if (headerValue.contains(",")) {
            String[] ips = headerValue.split(",");

            // Try to find the first public (non-private) IP
            for (String ip : ips) {
                ip = ip.trim();
                if (isValidIpAddress(ip) && !isPrivateIpAddress(ip)) {
                    return ip;
                }
            }

            // If no public IP found, return the first valid IP
            for (String ip : ips) {
                ip = ip.trim();
                if (isValidIpAddress(ip)) {
                    return ip;
                }
            }
        }

        // Single IP address
        String ip = headerValue.trim();
        if (isValidIpAddress(ip)) {
            return ip;
        }

        return null;
    }

    /**
     * Validate IP address format (IPv4 or IPv6)
     *
     * @param ip IP address string
     * @return true if valid IP format
     */
    public static boolean isValidIpAddress(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }

        // Check for "unknown" placeholder
        if ("unknown".equalsIgnoreCase(ip)) {
            return false;
        }

        // Validate IPv4
        if (IPV4_PATTERN.matcher(ip).matches()) {
            return isValidIpv4(ip);
        }

        // Validate IPv6
        if (IPV6_PATTERN.matcher(ip).find() || ip.contains(":")) {
            return isValidIpv6(ip);
        }

        return false;
    }

    /**
     * Validate IPv4 address
     */
    private static boolean isValidIpv4(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                return false;
            }

            for (String part : parts) {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Validate IPv6 address using InetAddress
     */
    private static boolean isValidIpv6(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr instanceof java.net.Inet6Address;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    /**
     * Check if IP address is in private/internal range
     *
     * @param ip IP address
     * @return true if private IP
     */
    public static boolean isPrivateIpAddress(String ip) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }

        // Check against known private IP prefixes
        for (String prefix : PRIVATE_IP_PREFIXES) {
            if (ip.startsWith(prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get client IP with detailed information
     * Useful for debugging and logging
     *
     * @param request HTTP request
     * @return IPInfo object with details
     */
    public static IpInfo getClientIpInfo(HttpServletRequest request) {
        if (request == null) {
            return new IpInfo("unknown", null, false, false);
        }

        // Try all headers
        for (String header : IP_HEADERS) {
            String ip = extractIpFromHeader(request, header);
            if (ip != null && !ip.isEmpty()) {
                boolean isPrivate = isPrivateIpAddress(ip);
                boolean isValid = isValidIpAddress(ip);
                return new IpInfo(ip, header, isValid, isPrivate);
            }
        }

        // Fallback to remote address
        String remoteAddr = request.getRemoteAddr();
        boolean isValid = isValidIpAddress(remoteAddr);
        boolean isPrivate = isPrivateIpAddress(remoteAddr);
        return new IpInfo(remoteAddr, "RemoteAddr", isValid, isPrivate);
    }

    /**
     * Get all IPs from the request (useful for debugging)
     *
     * @param request HTTP request
     * @return List of all IP addresses found in various headers
     */
    public static List<String> getAllIpAddresses(HttpServletRequest request) {
        return IP_HEADERS.stream()
                .map(request::getHeader)
                .filter(header -> header != null && !header.isEmpty() && !"unknown".equalsIgnoreCase(header))
                .map(String::trim)
                .distinct()
                .toList();
    }

    /**
     * IP address information
     */
    public static class IpInfo {
        private final String ipAddress;
        private final String source;
        private final boolean valid;
        private final boolean privateIp;

        public IpInfo(String ipAddress, String source, boolean valid, boolean privateIp) {
            this.ipAddress = ipAddress;
            this.source = source;
            this.valid = valid;
            this.privateIp = privateIp;
        }

        public String getIpAddress() {
            return ipAddress;
        }

        public String getSource() {
            return source;
        }

        public boolean isValid() {
            return valid;
        }

        public boolean isPrivateIp() {
            return privateIp;
        }

        public boolean isPublicIp() {
            return valid && !privateIp;
        }

        @Override
        public String toString() {
            return String.format("IP: %s, Source: %s, Valid: %s, Private: %s",
                    ipAddress, source, valid, privateIp);
        }
    }

    /**
     * Check if request is from a trusted proxy
     * Configure trusted proxy IPs in your application
     *
     * @param request HTTP request
     * @param trustedProxies List of trusted proxy IP addresses
     * @return true if request is from trusted proxy
     */
    public static boolean isFromTrustedProxy(HttpServletRequest request, List<String> trustedProxies) {
        if (trustedProxies == null || trustedProxies.isEmpty()) {
            return false;
        }

        String remoteAddr = request.getRemoteAddr();
        return trustedProxies.contains(remoteAddr);
    }

    /**
     * Get the real client IP considering trusted proxies
     *
     * @param request HTTP request
     * @param trustedProxies List of trusted proxy IPs
     * @return Real client IP
     */
    public static String getClientIpWithTrustedProxies(HttpServletRequest request, List<String> trustedProxies) {
        // If not from trusted proxy, use remote address directly
        if (!isFromTrustedProxy(request, trustedProxies)) {
            return request.getRemoteAddr();
        }

        // From trusted proxy, check X-Forwarded-For
        return getClientIpAddress(request);
    }

}