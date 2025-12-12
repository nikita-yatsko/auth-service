package com.authentication.service.Authentication_service.model.constants;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public enum ErrorMessage {

    USER_NOT_FOUNT_BY_USERNAME("User with username: %s not found"),
    USER_ALREADY_EXISTS("User with ID: %s already exists"),
    USERNAME_ALREADY_EXISTS("Username: %s already exists"),
    USER_HAS_TOKEN("User: %s already has token"),

    INVALID_TOKEN("Invalid token"),
    INVALID_REFRESH_TOKEN("Invalid refresh token"),
    EXPIRED_REFRESH_TOKEN("Expired refresh token"),
    REFRESH_TOKEN_ALREADY_EXISTS("Refresh token already exists"),
    REFRESH_TOKEN_NOT_FOUND("Refresh token not found"),
    CREATE_USER_ERROR("User creations failed"),
    ;

    private final String message;

    public String getMessage(Object... args) {
        return String.format(message, args);
    }
}
