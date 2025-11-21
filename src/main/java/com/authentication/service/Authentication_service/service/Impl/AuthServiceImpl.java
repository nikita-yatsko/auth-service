package com.authentication.service.Authentication_service.service.Impl;

import com.authentication.service.Authentication_service.mapper.UserMapper;
import com.authentication.service.Authentication_service.model.constants.ErrorMessage;
import com.authentication.service.Authentication_service.model.dto.AuthResponse;
import com.authentication.service.Authentication_service.model.dto.LoginRequest;
import com.authentication.service.Authentication_service.model.dto.RegisterUserRequest;
import com.authentication.service.Authentication_service.model.dto.TokenPair;
import com.authentication.service.Authentication_service.model.entity.AuthUser;
import com.authentication.service.Authentication_service.model.exception.DataExistException;
import com.authentication.service.Authentication_service.model.exception.InvalidRefreshToken;
import com.authentication.service.Authentication_service.model.exception.InvalidTokenException;
import com.authentication.service.Authentication_service.model.exception.NotFoundException;
import com.authentication.service.Authentication_service.repository.UserRepository;
import com.authentication.service.Authentication_service.security.model.CustomUserDetails;
import com.authentication.service.Authentication_service.service.AuthService;
import com.authentication.service.Authentication_service.service.JwtService;
import com.authentication.service.Authentication_service.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    protected final RefreshTokenService refreshTokenService;


    @Override
    @Transactional
    public AuthUser registerUser(RegisterUserRequest request) {
        if (userRepository.existsByUserId(request.getUserId()))
            throw new DataExistException(ErrorMessage.USER_ALREADY_EXISTS.getMessage(request.getUserId()));

        if (userRepository.existsByUsername(request.getUsername()))
            throw new DataExistException(ErrorMessage.USERNAME_ALREADY_EXISTS.getMessage(request.getUsername()));

        AuthUser authUser = userMapper.createAuthUser(request);
        authUser.setPassword(passwordEncoder.encode(request.getPassword()));

        return userRepository.save(authUser);
    }

    @Override
    @Transactional
    public TokenPair login(LoginRequest request) {
        // Authenticate user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return jwtService.generateTokePair(authentication);
    }


    @Override
    @Transactional
    public TokenPair refreshToken(String refreshTokenValue) {
        Integer userId = (int) jwtService.extractUserIdFromToken(refreshTokenValue);

        if (refreshTokenService.getRefreshToken(userId) == null)
            throw new NotFoundException(ErrorMessage.REFRESH_TOKEN_NOT_FOUND.getMessage());

        if (!jwtService.isValidToken(refreshTokenValue) || !jwtService.isRefreshToken(refreshTokenValue)) {
            throw new InvalidRefreshToken(ErrorMessage.INVALID_REFRESH_TOKEN.getMessage());
        }

        LocalDateTime expiration = jwtService.extractExpiration(refreshTokenValue);
        if (expiration.isBefore(LocalDateTime.now()))
            throw new InvalidTokenException(ErrorMessage.EXPIRED_REFRESH_TOKEN.getMessage());


        String username = jwtService.extractUsernameFromToken(refreshTokenValue);

        AuthUser user = userRepository.findUserByUserId(userId)
                .orElseThrow(() -> new UsernameNotFoundException(ErrorMessage.USER_NOT_FOUNT_BY_USERNAME.getMessage(username)));

        CustomUserDetails userDetails = new CustomUserDetails(user);

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

        SecurityContextHolder.getContext().setAuthentication(authentication); // put user to SecurityContext

        return jwtService.generateTokePair(authentication);
    }

    @Override
    public AuthResponse validateToken(String token) {
        if (!jwtService.isValidToken(token)) {
            return new AuthResponse(
                    false,
                    null,
                    null,
                    null
            );
        }

        return new AuthResponse(
                true,
                jwtService.extractUserIdFromToken(token),
                jwtService.extractRoleFromToken(token),
                jwtService.extractUsernameFromToken(token)
        );
    }
}
