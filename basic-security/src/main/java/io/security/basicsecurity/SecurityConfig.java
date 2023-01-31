package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
// Web Security 애노테이션 설정 클래스, 여러 클래스들을 import해서 실행시켜주는 애노테이션. ==> 웹 보안 활성화를 위해 필수적.
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 정책
        http
                .authorizeRequests()    // 요청에 따른 보안검사 시작
                .anyRequest().authenticated();  // 어떠한 요청에도 인증을 받도록 설정.

        // 인증 정책
        http
                .formLogin();
    }
}
