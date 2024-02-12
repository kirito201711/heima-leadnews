package com.heima.user.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.heima.model.common.dtos.ResponseResult;
import com.heima.model.common.enums.AppHttpCodeEnum;
import com.heima.model.user.dtos.LoginDto;
import com.heima.model.user.pojos.ApUser;
import com.heima.user.mapper.ApUserMapper;
import com.heima.user.service.ApUserService;
import com.heima.utils.common.AppJwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.DigestUtils;

import java.util.HashMap;
import java.util.Map;

@Service
@Transactional
@Slf4j
public class UserServiceImpl extends ServiceImpl<ApUserMapper, ApUser> implements ApUserService {
    /**
     * app端登陆功能
     *
     * @param loginDto
     * @return
     */
    @Override
    public ResponseResult login(LoginDto loginDto) {
        //1.正常登陆 用户名 密码
          if(StringUtils.isNotBlank(loginDto.getPhone()) && StringUtils.isNotBlank(loginDto.getPassword())){
              //1.1 手机号查询用户信息
              ApUser dbUser = getOne(Wrappers.<ApUser>lambdaQuery().eq(ApUser::getPhone, loginDto.getPhone()));
             if (dbUser == null){
                 return ResponseResult.errorResult(AppHttpCodeEnum.DATA_NOT_EXIST,"用户信息不存在");

             }
           //1.2比对密码
              String salt = dbUser.getSalt();
              String password = loginDto.getPassword();
              String pswd = DigestUtils.md5DigestAsHex((password + salt).getBytes());
             if (!pswd.equals(dbUser.getPassword())){
                 return ResponseResult.errorResult(AppHttpCodeEnum.LOGIN_PASSWORD_ERROR);
             }
              //1.3返回数据 jwt user
              String token = AppJwtUtil.getToken(dbUser.getId().longValue());
              Map<String,Object> map = new HashMap<>();
              map.put("token",token);
              dbUser.setSalt("");
              dbUser.setPassword("");
              map.put("user",dbUser);
              return ResponseResult.okResult(map);
          }else {
              Map<String,Object> map = new HashMap<>();
              map.put("token",AppJwtUtil.getToken(0L));
              return ResponseResult.okResult(map);
          }


    }
}
