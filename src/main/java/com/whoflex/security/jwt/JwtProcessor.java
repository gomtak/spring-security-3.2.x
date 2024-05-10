package com.whoflex.security.jwt;

import com.whoflex.security.CustomUserDetails;
import com.whoflex.security.CustomUserDetailsService;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtProcessor {
    public static final String AUTHORIZATION = "Authorization";
    @Value("${jwt.secret-key}")
    private String secretKey;
    @Value("${jwt.access-token}")
    private long accessTokenLifetimeInSeconds;
    @Value("${jwt.refresh-token}")
    private long refreshTokenLifetimeInSeconds;
    private static final String AUTHORITIES = "authorities";
    private static final String BEARER_TYPE = "Bearer";
    private final RedisTemplate<String, String> redisTemplate;
    private final CustomUserDetailsService customUserDetailsService;
    public String createAuthJwtToken(CustomUserDetails customUserDetails) {
        String authorities = customUserDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        SecretKey key = getSecretKey();

        var accessToken =
                Jwts.builder()
                        .subject(customUserDetails.getName())
                        .claim(AUTHORITIES, authorities)
                        .issuedAt(Date.from(Instant.now()))
                        .expiration(Date.from(Instant.now().plusSeconds(this.accessTokenLifetimeInSeconds)))
                        .signWith(key)
                        .compact();
        var refreshToken =
                Jwts.builder()
                        .subject(String.valueOf(customUserDetails.getName()))
                        .issuedAt(Date.from(Instant.now()))
                        .expiration(Date.from(Instant.now().plusSeconds(this.refreshTokenLifetimeInSeconds)))
                        .signWith(key)
                        .compact();
        redisTemplate.opsForValue().set(customUserDetails.getName() + "-REFRESH", refreshToken);
        return String.join(" ", BEARER_TYPE, accessToken);
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        if (bearerToken != null && bearerToken.startsWith(BEARER_TYPE)) {
            return bearerToken.substring(7);
        }
        return bearerToken;
    }

    public Authentication getAuthentication(String token) throws JwtException {
        String name = Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload().getSubject();
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(name);
        return new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
    }
}
