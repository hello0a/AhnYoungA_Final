package com.auth.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface LoginHistoryMapper {
    
    int insert(
        @Param("userNo") Long userNo,
        @Param("ip") String ip,
        @Param("agent") String agent,
        @Param("success") boolean success
    );
}
