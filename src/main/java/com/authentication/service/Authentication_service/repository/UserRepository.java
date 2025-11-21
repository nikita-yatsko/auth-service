package com.authentication.service.Authentication_service.repository;

import com.authentication.service.Authentication_service.model.entity.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<AuthUser, Integer> {

    Optional<AuthUser> findByUsername(String username);

    Optional<AuthUser> findUserByUserId(Integer userId);

    Boolean existsByUsername(String username);

    Boolean existsByUserId(Integer userId);
}
