package com.derteuffel.security.configurations;

import com.derteuffel.security.securities.JwtAuthorizationFilter;
import com.derteuffel.security.securities.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final String WHITE_LIST[] = {
            "/swagger-ui/index.html",
            "/swagger-ui.html/**",
            "/swagger-ui.html",
            "/v2/api-docs",
            "/api/auth/login"
    };


    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //Cross-origin-resource-sharing
        //http.authorizeRequests().antMatchers(WHITE_LIST).permitAll();

        http.cors()
                .and()
                .authorizeRequests()
                //.antMatchers(WHITE_LIST).permitAll()
                //These are public pages.
                .antMatchers("/resources/**", "/error", "/api/user/**","/api/produits/all/**","/api/commandes/**").permitAll()
                //These can be reachable for just have admin role.
                .antMatchers("/api/boutiques/**","/api/produits/admin/**").hasAnyRole("ADMIN","ROOT","SELLER")
                //all remaining paths should need authentication.
                .anyRequest().fullyAuthenticated()
                .and()
                //logout will log the user out by invalidate session.
                .logout().permitAll()
                .logoutRequestMatcher(new AntPathRequestMatcher("/api/auth/logout", "POST")).and()
                //login form and path
                .formLogin().loginPage("/api/auth/login")
                .and()
                //enable basic authentication. Http header: basis username:password
                .httpBasic().and()
                //Cross side request forgery.
                .csrf().disable();

        http.addFilter(new JwtAuthorizationFilter(authenticationManager(), tokenProvider));
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    //Cross origin resource sharing.
    @Bean
    public WebMvcConfigurer corsConfigurer(){
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**").allowedOrigins("*").allowedMethods("*");
            }
        };
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
