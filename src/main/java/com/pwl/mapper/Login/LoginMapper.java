package com.pwl.mapper.Login;

import org.apache.ibatis.annotations.Mapper;

import com.pwl.domain.Login.UserInfo;

@Mapper
public interface LoginMapper {
    
    // Search for User Information
    UserInfo getUserInfo(UserInfo userinfo);
    
    // Password Update
    void updatePassword(UserInfo userinfo);
}
