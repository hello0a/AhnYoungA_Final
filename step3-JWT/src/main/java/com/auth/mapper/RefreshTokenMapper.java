package com.auth.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.auth.domain.RefreshToken;

@Mapper
public interface RefreshTokenMapper {
    
    int insert(RefreshToken refreshToken);
    RefreshToken findByTokenHash(@Param("tokenHash") String tokenHash);
    int revokedByTokenHash(@Param("tokenHash") String tokenHash);
    int revokedAllByUserNo(@Param("userNo") Long userNo);
}
