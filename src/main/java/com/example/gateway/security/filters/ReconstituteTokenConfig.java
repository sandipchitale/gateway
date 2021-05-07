package com.example.gateway.security.filters;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class ReconstituteTokenConfig {

    public static class ReconstituteTokenFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                FilterChain filterChain) throws ServletException, IOException {
            try {
                String authorizationHeader = reconstituteAuthorizationHeader(request, response);
                if (authorizationHeader != null) {
                    MutableHttpServletRequest requestWrapper = new MutableHttpServletRequest(request);
                    requestWrapper.putHeader(HttpHeaders.AUTHORIZATION, authorizationHeader);
                    filterChain.doFilter(requestWrapper, response);
                } else {
                    filterChain.doFilter(request, response);
                }
            } catch (InsufficientAuthenticationException iae) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }

        }
    }

    private static String reconstituteAuthorizationHeader(HttpServletRequest request, HttpServletResponse response) {
        String access_token_payload = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (access_token_payload != null) {
            if (access_token_payload.startsWith(OAuth2AccessToken.BEARER_TYPE + " ")) {
                access_token_payload = access_token_payload.substring((OAuth2AccessToken.BEARER_TYPE + " ").length());
                System.out.println("Access token payload: " + access_token_payload);
                if (access_token_payload.indexOf(".") != -1) {
                    // Already a full JWT
                    return access_token_payload;
                }
                Cookie[] cookies = request.getCookies();
                for (int i = 0; i < cookies.length; i++) {
                    Cookie cookie = cookies[i];
                    if (OAuth2AccessToken.ACCESS_TOKEN.equals(cookie.getName())) {
                        String accessTokenHeeaderSignature = cookie.getValue();
                        String[] accessTokenParts = accessTokenHeeaderSignature.split("\\.");
                        if (accessTokenParts.length == 2) {
                            String authorizationHeader = accessTokenParts[0] + "." + access_token_payload + "." + accessTokenParts[1];
                            System.out.println("Authorization: " + authorizationHeader);
                            return authorizationHeader;
                        }
                    }
                }
                throw new InsufficientAuthenticationException("Insufficient authnetication.");
            }
        }
        return null;
    }

    @Bean
    public FilterRegistrationBean<ReconstituteTokenFilter> userFilter() {
        FilterRegistrationBean<ReconstituteTokenFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new ReconstituteTokenFilter());
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registrationBean;
    }

    final static class MutableHttpServletRequest extends HttpServletRequestWrapper {
        // holds custom header and value mapping
        private final Map<String, String> customHeaders;

        public MutableHttpServletRequest(HttpServletRequest request){
            super(request);
            this.customHeaders = new HashMap<String, String>();
        }

        public void putHeader(String name, String value){
            this.customHeaders.put(name, value);
        }

        public String getHeader(String name) {
            // check the custom headers first
            String headerValue = customHeaders.get(name);

            if (headerValue != null){
                return headerValue;
            }
            // else return from into the original wrapped object
            return ((HttpServletRequest) getRequest()).getHeader(name);
        }

        public Enumeration<String> getHeaderNames() {
            // create a set of the custom header names
            Set<String> set = new HashSet<String>(customHeaders.keySet());

            // now add the headers from the wrapped request object
            @SuppressWarnings("unchecked")
            Enumeration<String> e = ((HttpServletRequest) getRequest()).getHeaderNames();
            while (e.hasMoreElements()) {
                // add the names of the request headers into the list
                String n = e.nextElement();
                set.add(n);
            }

            // create an enumeration from the set and return
            return Collections.enumeration(set);
        }
    }
}
