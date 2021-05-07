package com.example.gateway.clients;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@Order(-10)
public class WebappLoginFilterConfig extends WebSecurityConfigurerAdapter {

    private static class WebappLoginFilter extends OncePerRequestFilter {
        private static final String REFRESH_TOKEN = "refresh_token";
        private static final String PASSWORD = "password";
        private static String DEFAULT_OUATH_TOKEN_PATH = "/oauth/token";

        private String basicHeaderBase64ClientIdClientSecret
                = Base64.getEncoder().encodeToString(("client:secret").getBytes(StandardCharsets.UTF_8));
        private String oauthTokenPath;

        public WebappLoginFilter() {
            this.oauthTokenPath = DEFAULT_OUATH_TOKEN_PATH;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                FilterChain filterChain) throws ServletException, IOException {
            String grant_type = request.getParameter(OAuth2Utils.GRANT_TYPE);
            String client_id = request.getParameter(OAuth2Utils.CLIENT_ID);
            if ((PASSWORD.equals(grant_type) || REFRESH_TOKEN.equals(grant_type))) {
                if ("client".equals(client_id)) {
                    MutableHttpServletRequest mutableRequest = new MutableHttpServletRequest(request);
                    // Inject header for clientId:clientSercret
                    mutableRequest.putHeader(HttpHeaders.AUTHORIZATION, "Basic " + basicHeaderBase64ClientIdClientSecret);
                    if ("/webapp-login".equals(request.getRequestURI())) {
                        mutableRequest.putParameter(OAuth2Utils.GRANT_TYPE, PASSWORD);
                    } else {
                        mutableRequest.putParameter(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN);
                    }
                    // Forward request to Authorization Server
                    request.getRequestDispatcher(oauthTokenPath).forward(mutableRequest, response);
                } else {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Incorrect client_id.");
                }
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing grant_type and client_id.");
            }
        }

    }

    public WebappLoginFilter webappLoginFilter() {
        return new WebappLoginFilter();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.requestMatchers()
                .mvcMatchers("/webapp-login", "/webapp-refresh-token")
            .and()
            .csrf()
                .disable()
            .authorizeRequests()
                .anyRequest()
                    .permitAll();
        // @formatter:on

        http.addFilterBefore(webappLoginFilter(), BasicAuthenticationFilter.class);
    }

    final static class MutableHttpServletRequest extends HttpServletRequestWrapper {
        // holds custom header and value mapping
        private final Map<String, String> customHeaders;
        private final Map<String, String[]> customParameters;

        public MutableHttpServletRequest(HttpServletRequest request){
            super(request);
            this.customHeaders = new HashMap<String, String>();
            this.customParameters = new HashMap<String, String[]>();
        }

        public void putHeader(String name, String value) {
            this.customHeaders.put(name, value);
        }

        public void putParameter(String name, String value){
            this.customParameters.put(name.toLowerCase(), new String[] { value });
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

        @Override
        public Map<String, String[]> getParameterMap() {

            Map<String, String[]> unionMap = new LinkedHashMap<>();
            unionMap.putAll(customParameters);
            unionMap.putAll(super.getParameterMap());
            return Collections.unmodifiableMap(unionMap);
        }

        public String getParameter(String paramName) {
            // check the custom headers first
            String[] parameterValueArray = customParameters.get(paramName.toLowerCase());

            if (parameterValueArray != null && parameterValueArray.length > 0) {
                return parameterValueArray[0];
            }
            // else return from into the original wrapped object
            return ((HttpServletRequest) getRequest()).getParameter(paramName);
        }
    }

}
