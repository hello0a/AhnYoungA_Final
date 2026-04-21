package com.auth.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.auth.domain.User;

@Mapper
public interface UserMapper {
    // 이메일로 회원 정보 조회
    User findByEmail(String email);
    // no로 회원 정보 조회
    User findByNo(Long no);
    // 사용자 정보 등록
    int insertUser(User user);
    // 비밀번호 변경
    int updatePassword(@Param("no") Long no, @Param("password") String password);
}
/**
 * @Mapper 개념/사용 이유
 * : MyBatis 인터페이스 -> SQL 연결
 *  - 구현체 자동 생성
 */
