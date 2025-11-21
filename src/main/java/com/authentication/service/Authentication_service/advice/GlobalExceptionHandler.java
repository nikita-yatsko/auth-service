package com.authentication.service.Authentication_service.advice;

import com.authentication.service.Authentication_service.model.exception.InvalidRefreshToken;
import com.authentication.service.Authentication_service.model.exception.InvalidTokenException;
import com.authentication.service.Authentication_service.model.exception.NotFoundException;
import com.authentication.service.Authentication_service.model.response.ErrorResponse;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?>handleAuthenticationException(final AuthenticationException ex, final HttpServletRequest request) {
        log.error(ex.getMessage());

        return buildErrorResponse(ex, HttpStatus.BAD_REQUEST, request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?>handleAccessDeniedException(final AccessDeniedException ex, final HttpServletRequest request) {
        log.error(ex.getMessage());

        return buildErrorResponse(ex, HttpStatus.FORBIDDEN, request);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<?>handleUsernameNotFoundException(final UsernameNotFoundException ex, final HttpServletRequest request) {
        log.error(ex.getMessage());

        return buildErrorResponse(ex, HttpStatus.NOT_FOUND, request);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<?>handleInvalidTokenException(final InvalidTokenException ex, final HttpServletRequest request) {
        log.error(ex.getMessage());

        return buildErrorResponse(ex, HttpStatus.UNAUTHORIZED, request);
    }

    @ExceptionHandler(InvalidRefreshToken.class)
    public ResponseEntity<?>handleInvalidRefreshToken(final InvalidRefreshToken ex, final HttpServletRequest request) {
        log.error(ex.getMessage());

        return buildErrorResponse(ex, HttpStatus.UNAUTHORIZED, request);
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<?>handleExpiredJwtException(final ExpiredJwtException ex, final HttpServletRequest request) {
        log.error(ex.getMessage());

        return buildErrorResponse(ex, HttpStatus.UNAUTHORIZED, request);
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<?>handleNotFoundException(final NotFoundException ex, final HttpServletRequest request) {
        log.error(ex.getMessage());

        return buildErrorResponse(ex, HttpStatus.NOT_FOUND, request);
    }

    private ResponseEntity<ErrorResponse> buildErrorResponse (Exception e, HttpStatus status, HttpServletRequest request) {
        ErrorResponse response = new ErrorResponse(
                LocalDateTime.now(),
                status.value(),
                status.getReasonPhrase(),
                e.getMessage(),
                request.getRequestURI()
        );

        return ResponseEntity.status(status).body(response);
    }
}
