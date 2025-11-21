package com.authentication.service.Authentication_service.service;

import com.authentication.service.Authentication_service.model.entity.RefreshToken;
import org.springframework.stereotype.Service;

@Service
public interface RefreshTokenService {

    void saveRefreshToken(String refreshToken, Integer userId, long expiresAt);

    RefreshToken getRefreshToken(Integer userId);

    void deleteRefreshToken(Integer userId);
}
