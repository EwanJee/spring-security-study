package org.springsecuritystudy

import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.CurrentSecurityContext
import org.springframework.security.core.context.SecurityContext
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class WelcomeController {
    @GetMapping("/")
    fun welcome(): String = "Welcome to Spring Security Study"

    @GetMapping("/login")
    fun login(): String = "Login Page"

    @GetMapping("/home")
    fun home(): String = "Home Page"

    @GetMapping("/anonymous")
    fun anonymous(): String = "Anonymous Page"

    @GetMapping("/authentication")
    fun authentication(authentication: Authentication): String {
        if (authentication is AnonymousAuthenticationToken) {
            return "Anonymous Authentication"
        }
        return "null"
    }

    @GetMapping("/anonymousContext")
    fun anonymousContext(
        @CurrentSecurityContext context: SecurityContext,
    ): String = context.authentication.name
}
