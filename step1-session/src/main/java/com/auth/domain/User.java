package com.auth.domain;

import lombok.Data;

@Data
public class User {
    private Long no;
    private String id;
    private String email;
    private String password;
    private String name;
}
