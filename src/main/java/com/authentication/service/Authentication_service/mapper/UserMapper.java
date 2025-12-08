package com.authentication.service.Authentication_service.mapper;

import com.authentication.service.Authentication_service.model.dto.RegisterUserRequest;
import com.authentication.service.Authentication_service.model.entity.AuthUser;
import com.authentication.service.Authentication_service.model.entity.UserRequest;
import com.authentication.service.Authentication_service.model.enums.Role;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.NullValuePropertyMappingStrategy;

@Mapper(
        componentModel = "spring",
        nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE,
        imports = {Role.class}
)
public interface UserMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "role", expression = "java(Role.USER)")
    AuthUser createAuthUser(RegisterUserRequest request);

    @Mapping(target = "userId", source = "userId")
    UserRequest createUserRequest(RegisterUserRequest request, Integer userId);
}
