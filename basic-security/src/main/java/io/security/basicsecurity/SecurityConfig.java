package io.security.basicsecurity;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
// Web Security 애노테이션 설정 클래스, 여러 클래스들을 import해서 실행시켜주는 애노테이션. ==> 웹 보안 활성화를 위해 필수적.
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 인가 정책
        http
                .authorizeRequests()    // 요청에 따른 보안검사 시작
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();  // 어떠한 요청에도 인증을 받도록 설정.

        // 인증 정책
        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();

                        // 원래 사용자가 인증 전 가고자 했던 페이지가 저장되어 있음.
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl); // 인증 성공 후 세션에 저장되어있던 이전의 요청 정보를 꺼내온 후 redirect
                    }
                })
        ;

//        http
//                .logout()
//        ;
//
        /**
         * Remember me 인증
         */
//        http
//                .rememberMe()
//                .userDetailsService(userDetailsService) // 미리 UserDetailsService를 Autowired 해줌.
//        ;

        /**
         * 동시 세션 제어
         */
//        http
//                .sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false)
//        ;

        /**
         * 세션 고정 보호
         */
//        http
//                .sessionManagement()
//                .sessionFixation().changeSessionId()
//        ;


        /**
         * 인증예외, 인가예외 처리
         */
        http
                .exceptionHandling()
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })
        ;
    }
}
