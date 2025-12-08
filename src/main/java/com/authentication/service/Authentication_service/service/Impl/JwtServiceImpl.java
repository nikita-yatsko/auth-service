package com.authentication.service.Authentication_service.service.Impl;

import com.authentication.service.Authentication_service.model.constants.ErrorMessage;
import com.authentication.service.Authentication_service.model.dto.TokenPair;
import com.authentication.service.Authentication_service.model.exception.InvalidTokenException;
import com.authentication.service.Authentication_service.security.model.CustomUserDetails;
import com.authentication.service.Authentication_service.service.JwtService;
import com.authentication.service.Authentication_service.service.RefreshTokenService;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class JwtServiceImpl implements JwtService {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expirationMs}")
    private long jwtExpirationMs;

    @Value("${app.jwt.refreshExpirationMs}")
    private long refreshExpirationMs;

    private final RefreshTokenService refreshTokenService;


    // generate token pair
    public TokenPair generateTokePair(Authentication authentication) {
        CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();

        String accessToken = generateToken(user, jwtExpirationMs, "access");
        String refreshToken = generateToken(user, refreshExpirationMs, "refresh");

        Integer userId = (int) extractUserIdFromToken(refreshToken);
        refreshTokenService.saveRefreshToken(refreshToken, userId, refreshExpirationMs);

        return new TokenPair(accessToken, refreshToken);
    }

    // generate token
    private String generateToken(CustomUserDetails user, long expirationMs, String tokenType) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("role", user.getRole());
        claims.put("tokenType", tokenType);

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + expirationMs);

        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(user.getUsername())
                .addClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(getSignKey())
                .compact();
    }

    // Validate token
    public Boolean isValidToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            throw new InvalidTokenException(ErrorMessage.INVALID_TOKEN.getMessage());
        }
    }

    // Validate if token is refresh token
    public Boolean isRefreshToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        String tokenType = claims.get("tokenType", String.class);
        return "refresh".equals(tokenType);
    }

    // extract username from token
    public String extractUsernameFromToken(String token) {
        return  Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // extract expirations from token
    public LocalDateTime extractExpiration(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        Date expiration = claims.getExpiration();
        return LocalDateTime.ofInstant(expiration.toInstant(), ZoneId.systemDefault());
    }

    // extract userID from token
    public long extractUserIdFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.get("userId", Long.class);
    }

    // extract role from token
    public String extractRoleFromToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

        String role = claims.get("role", String.class);
        log.info("Extracted role from token: {}", role);
        return role;
    }

    private Key getSignKey() {
        byte[] keyBytes = java.util.Base64.getDecoder().decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}