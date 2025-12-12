package com.authentication.service.Authentication_service.service.Impl;

import com.authentication.service.Authentication_service.model.entity.UserRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

@Service
public class UserClient {

    private final WebClient webClient;

    public UserClient(WebClient.Builder builder) {
        this.webClient = builder.baseUrl("http://user-service:8083").build();
    }

    public UserRequest createUser(UserRequest request) {
        return webClient.post()
                .uri("/api/user/create")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .bodyValue(request)
                .retrieve()
                .bodyToMono(UserRequest.class)
                .block();
    }

}
