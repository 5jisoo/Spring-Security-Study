package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

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
                .formLogin()
                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {    // 로그인에 성공한 경우 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName());
                        response.sendRedirect("/"); // redirect
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {    // 로그인에 실패한 경우 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception" + exception.getMessage());
                        response.sendRedirect("/loginPage");
                    }
                })
                .permitAll()    // "/loginPage"는 인증이 없어도 접근을 허락함.
        ;

        http
                .logout()
                .logoutUrl("/logout")   // default: /logout
                .logoutSuccessUrl("/login")   // 스프링 시큐리티에서는 로그아웃 처리를 POST 방식으로 해야 함.
                .addLogoutHandler(new LogoutHandler() {

                    // 원하는 기능 추가를 위해 직접 LogoutHandler()를 익명 클래스로 구현.
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();   // 세션 무효화 작업
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");    // 로그인 페이지로 이동하게 함.
                    }
                })
                .deleteCookies("remember-me")   // 서버에서 만든 쿠키명을 적어줌.
        ;

    }
}
