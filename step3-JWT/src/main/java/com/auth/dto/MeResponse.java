package com.auth.dto;

import com.auth.domain.User;

import lombok.Data;

@Data
public class MeResponse {
    private Long no;
    private String email;
    private String name;

    public MeResponse(User user) {
        this.no = user.getNo();
        this.email = user.getEmail();
        this.name = user.getName();
    }
}
