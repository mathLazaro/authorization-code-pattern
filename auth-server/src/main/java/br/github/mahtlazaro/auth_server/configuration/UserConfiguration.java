package br.github.mahtlazaro.auth_server.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.TestingAuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class UserConfiguration {

    @Bean
    public UserDetails testUser() {

        return User.builder()
                .username("user")
                .password("{noop}123")
                .authorities("ADMIN")
                .build();
    }

    @Bean
    public UserDetailsService userDetailsManager(UserDetails user) {

        return new InMemoryUserDetailsManager(user);
    }
}
