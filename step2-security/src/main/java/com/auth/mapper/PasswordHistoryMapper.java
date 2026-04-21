package com.auth.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface PasswordHistoryMapper {
    List<String> findByUser(Long userNo);
    int insert(Long userNo, String password);
}
