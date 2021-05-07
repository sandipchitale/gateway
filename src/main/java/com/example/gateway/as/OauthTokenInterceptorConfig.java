package com.example.gateway.as;

import javax.servlet.http.HttpServletResponse;

import com.example.gateway.as.utils.SplitTokenUtils;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Configuration
@Aspect
public class OauthTokenInterceptorConfig {
    @Around("execution(* org.springframework.security.oauth2.provider.endpoint.TokenEndpoint.postAccessToken(..))")
    private Object around(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
        ResponseEntity<OAuth2AccessToken> oAuth2AccessTokenResponse = (ResponseEntity<OAuth2AccessToken>) proceedingJoinPoint
                .proceed();

        DefaultOAuth2AccessToken defaultOAuth2AccessToken =
                (DefaultOAuth2AccessToken) oAuth2AccessTokenResponse.getBody();

        HttpServletResponse httpServletResponse =
                ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();

        SplitTokenUtils.splitToken(defaultOAuth2AccessToken, httpServletResponse);
        return oAuth2AccessTokenResponse;
    }

}
