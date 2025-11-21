package com.authentication.service.Authentication_service.service;

import com.authentication.service.Authentication_service.model.dto.TokenPair;
import org.springframework.security.core.Authentication;

import java.time.LocalDateTime;

public interface JwtService {

    TokenPair generateTokePair(Authentication authentication);

    Boolean isValidToken(String token);

    Boolean isRefreshToken(String token);

    String extractUsernameFromToken(String token);

    LocalDateTime extractExpiration(String token);

    long extractUserIdFromToken(String token);

    String extractRoleFromToken(String token);


}
