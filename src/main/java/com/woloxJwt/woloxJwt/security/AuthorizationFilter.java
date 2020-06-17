package com.woloxJwt.woloxJwt.security;

import com.woloxJwt.woloxJwt.errors.AuthoritationException;
import com.woloxJwt.woloxJwt.errors.AuthenticationHandlerError;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.ArrayList;

import static com.woloxJwt.woloxJwt.constants.SecurityConstants.*;

public class AuthorizationFilter extends BasicAuthenticationFilter {

    public AuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        try {
            UsernamePasswordAuthenticationToken authentication = authenticate(request);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } catch (AuthoritationException e) {
            AuthenticationHandlerError.getException(response, e.getStatus(), e.getErrorCode(), e.getMessage());
        }
    }

    private UsernamePasswordAuthenticationToken authenticate(final HttpServletRequest request) {
        final String token = request.getHeader(HEADER_NAME);

        if (token != null && !token.isEmpty()) {
            try {
                final Claims user = Jwts.parser()
                        .setSigningKey(Keys.hmacShaKeyFor(KEY.getBytes()))
                        .parseClaimsJws(token)
                        .getBody();

                if (user != null) {
                    return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
                }
                throw new AuthoritationException("User not authenticated", HttpStatus.UNAUTHORIZED);
            } catch (Exception e) {
                throw new AuthoritationException("Invalid token", HttpStatus.UNAUTHORIZED);
            }
        }
        throw new AuthoritationException("Bad authorization request", HttpStatus.BAD_REQUEST);
    }
}
