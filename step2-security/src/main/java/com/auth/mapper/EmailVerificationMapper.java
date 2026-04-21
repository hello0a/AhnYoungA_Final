package com.auth.mapper;

import java.time.LocalDateTime;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface EmailVerificationMapper {
    int insert(
        @Param("userNo") Long userNo,
        @Param("email") String email,
        @Param("code") String code,
        @Param("expiry") LocalDateTime expiry
    );
}
