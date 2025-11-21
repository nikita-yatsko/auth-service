package com.authentication.service.Authentication_service.service.Impl;

import com.authentication.service.Authentication_service.mapper.RefreshTokenMapper;
import com.authentication.service.Authentication_service.model.constants.ErrorMessage;
import com.authentication.service.Authentication_service.model.entity.RefreshToken;
import com.authentication.service.Authentication_service.model.exception.NotFoundException;
import com.authentication.service.Authentication_service.repository.RefreshTokenRepository;
import com.authentication.service.Authentication_service.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

@RequiredArgsConstructor
@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenMapper refreshTokenMapper;

    @Override
    public void saveRefreshToken(String refreshToken, Integer userId, long expiresAt) {
        deleteRefreshToken(userId);

        RefreshToken refreshTokenEntity = refreshTokenMapper.createToken(refreshToken, userId, LocalDateTime.now().plus(expiresAt, ChronoUnit.MILLIS) );
        refreshTokenRepository.save(refreshTokenEntity);
    }

    @Override
    public RefreshToken getRefreshToken(Integer userId) {
        return refreshTokenRepository.findRefreshTokenByUserId(userId)
                .orElseThrow(() -> new NotFoundException(ErrorMessage.REFRESH_TOKEN_NOT_FOUND.getMessage()));
    }

    @Override
    public void deleteRefreshToken(Integer userId) {
        if ( refreshTokenRepository.findRefreshTokenByUserId(userId).isPresent())
            refreshTokenRepository.deleteByUserId(userId);
    }
}
