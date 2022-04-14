package com.kys95.jwt.config;

import com.kys95.jwt.config.jwt.JwtAuthenticationFilter;
import com.kys95.jwt.config.jwt.JwtAuthorizationFilter;
import com.kys95.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CorsConfig corsConfig;

    @Autowired
    private UserRepository userRepository;



    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilter(corsConfig.corsFilter())  //@CrossOrigin(인증없는 경우), security filter에 등록(인증있는 경우)
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //session 사용x
                .and()
                .formLogin().disable()  //jwt 서버이므로 formLogin 사용x
                .httpBasic().disable()
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))   //AuthenticationManager
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
                .authorizeRequests()
                .antMatchers("/api/v1/usr/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();


    }
}
