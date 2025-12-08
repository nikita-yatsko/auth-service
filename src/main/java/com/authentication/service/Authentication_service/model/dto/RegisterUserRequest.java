package com.authentication.service.Authentication_service.model.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RegisterUserRequest {

    @Size(min = 3, max = 30, message = "Username should be between 3 and 30")
    private String username;

    private String password;

    @NotBlank(message = "Name can not be empty")
    @Size(min = 2, max = 50, message = "Name must be between 2 and 50 characters")
    private String name;

    @NotBlank(message = "Surname can not be empty")
    @Size(min = 2, max = 50, message = "Surname must be between 2 and 50 characters")
    private String surname;

    @JsonFormat(pattern = "yyyy-MM-dd")
    @Past(message = "Birth date must be in the past")
    private LocalDate birthDate;

    @Email(message = "Email should be valid")
    @NotBlank(message = "Email cannot be empty")
    private String email;
}
