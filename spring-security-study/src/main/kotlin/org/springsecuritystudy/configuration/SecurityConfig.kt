package org.springsecuritystudy.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@Configuration
class SecurityConfig {
    //    @Bean
//    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
//        http
//            .authorizeHttpRequests { auth -> auth.anyRequest().authenticated() }
//            .formLogin {
//                it
//                    .loginPage("/login")
//                    .loginProcessingUrl("/loginProc") // post method
//                    .defaultSuccessUrl("/", true)
//                    .failureUrl("/failed")
//                    .usernameParameter("userId")
//                    .passwordParameter("passwd")
//                    .successHandler(
//                        AuthenticationSuccessHandler { request, response, authentication ->
//                            println("authentication: $authentication")
//                            response.sendRedirect("/home")
//                        }, // defaultSuccessURL 보다 이게 우선시 된다.
//                    .failureHandler(
//                        AuthenticationFailureHandler { request, response, exception ->
//                            println("exception: $exception")
//                            response.sendRedirect("/login")
//                        },
//                    ).permitAll()
//            }
//        return http.build()
//    }
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { auth -> auth.anyRequest().authenticated() }
            .formLogin(Customizer.withDefaults())
            .rememberMe {
                it
//                    .alwaysRemember(true)
                    .tokenValiditySeconds(3600)
                    .userDetailsService(inMemoryUserDetailsManager())
                    .rememberMeParameter("remember")
                    .rememberMeCookieName("remember")
                    .key("security")
            }
        return http.build()
    }

    @Bean
    fun inMemoryUserDetailsManager(): InMemoryUserDetailsManager {
        val user: UserDetails =
            User
                .withUsername("user")
                .password("{noop}1111")
                .roles("USER")
                .build()
        return InMemoryUserDetailsManager(user)
    }
}
