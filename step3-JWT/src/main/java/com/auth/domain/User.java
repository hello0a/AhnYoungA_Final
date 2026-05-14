package com.auth.domain;

import java.io.Serializable;

import lombok.Data;

@Data
public class User implements Serializable {

    private static final long serialVersionUID = 1L;

    private Long no;
    private String id;
    private String email;
    private String password;
    private String name;
    // 2단계
    private int loginFailCount;
    private boolean locked;
}
