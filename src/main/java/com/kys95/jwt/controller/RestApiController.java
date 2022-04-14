package com.kys95.jwt.controller;

import com.kys95.jwt.model.User;
import com.kys95.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user){

        String lawPassword = user.getPassword();
        user.setPassword(bCryptPasswordEncoder.encode(lawPassword));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입 완료";
    }

    //user,manager,admin 권한 접근 가능
    @GetMapping("api/v1/user")
    public String user(){
        return "user";
    }

    //manager, admin 권한 접근 가능
    @GetMapping("api/v1/manager")
    public String manager(){
        return "manager";
    }

    //admin 권한 접근 가능
    @GetMapping("api/v1/admin")
    public String admin(){
        return "admin";
    }
}
