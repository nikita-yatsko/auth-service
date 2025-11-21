package com.authentication.service.Authentication_service.mapper;

import com.authentication.service.Authentication_service.model.entity.RefreshToken;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValuePropertyMappingStrategy;

import java.time.LocalDateTime;

@Mapper(
        componentModel = "spring",
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE
)
public interface RefreshTokenMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", expression = "java(java.time.LocalDateTime.now())")
    @Mapping(target = "token", source = "refreshToken")
    @Mapping(target = "expiresAt", source = "expiresAt")
    RefreshToken createToken(String refreshToken, Integer userId, LocalDateTime expiresAt);
}
