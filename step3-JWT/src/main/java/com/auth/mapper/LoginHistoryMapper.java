package com.auth.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.auth.domain.LoginHistory;

@Mapper
public interface LoginHistoryMapper {
    
    int insert(
        @Param("userNo") Long userNo,
        @Param("ip") String ip,
        @Param("agent") String agent,
        @Param("success") boolean success
    );

    List<LoginHistory> findByUserNo(@Param("userNo") Long userNo);
}
