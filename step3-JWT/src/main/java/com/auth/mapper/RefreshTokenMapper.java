package com.auth.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.auth.domain.RefreshToken;

@Mapper
public interface RefreshTokenMapper {
    
    int insert(RefreshToken refreshToken);
    RefreshToken findByTokenHash(@Param("tokenHash") String tokenHash);
    int revokeByTokenHash(@Param("tokenHash") String tokenHash);
    int revokeAllByUserNo(@Param("userNo") Long userNo);
}
