package com.auth.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface LoginHistoryMapper {
    
    int insert(Long userNo, String ip, String agent, boolean success);
}
