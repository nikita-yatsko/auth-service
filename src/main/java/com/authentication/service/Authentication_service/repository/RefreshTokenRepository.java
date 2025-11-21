package com.authentication.service.Authentication_service.repository;

import com.authentication.service.Authentication_service.model.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {

    Optional<RefreshToken> findRefreshTokenByUserId(Integer userId);

    @Modifying
    @Query(value = "DELETE FROM refresh_tokens rf WHERE user_id = :userId", nativeQuery = true)
    void deleteByUserId(Integer userId);
}
