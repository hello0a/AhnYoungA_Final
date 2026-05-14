package com.auth.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface PasswordHistoryMapper {
    List<String> findByUser(@Param("userNo") Long userNo);
    int insert(@Param("userNo") Long userNo, @Param("password") String password);
}
