package com.authentication.service.Authentication_service.model.entity;

import lombok.Data;
import lombok.ToString;

import java.time.LocalDate;

@Data
@ToString
public class UserRequest {

    private Integer userId;
    private String name;
    private String surname;
    private LocalDate birthDate;
    private String email;
}
