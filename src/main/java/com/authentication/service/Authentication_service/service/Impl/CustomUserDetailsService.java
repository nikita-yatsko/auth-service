package com.authentication.service.Authentication_service.service.Impl;

import com.authentication.service.Authentication_service.model.constants.ErrorMessage;
import com.authentication.service.Authentication_service.security.model.CustomUserDetails;
import com.authentication.service.Authentication_service.model.entity.AuthUser;
import com.authentication.service.Authentication_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(ErrorMessage.USER_NOT_FOUNT_BY_USERNAME.getMessage(username)));

        return new CustomUserDetails(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getRole().name()
        );
        }

    private Collection<? extends GrantedAuthority> getAuthority(AuthUser user) {
        GrantedAuthority authority = new SimpleGrantedAuthority(user.getRole().name());
        return List.of(authority);
    }
}
