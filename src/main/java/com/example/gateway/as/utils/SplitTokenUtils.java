package com.example.gateway.as.utils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

public class SplitTokenUtils {

    public static void splitToken(DefaultOAuth2AccessToken defaultOAuth2AccessToken,
            HttpServletResponse httpServletResponse) {
        String accessTokenValue = defaultOAuth2AccessToken.getValue();
        String[] accessTokenParts = accessTokenValue.split("\\.");
        // JWT payload only
        defaultOAuth2AccessToken.setValue(accessTokenParts[1]);
        // JWT header.signature
        Cookie accessTokenCookie = new Cookie(OAuth2AccessToken.ACCESS_TOKEN,
                accessTokenParts[0] + "." + accessTokenParts[2]);
        accessTokenCookie.setMaxAge(-1);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        httpServletResponse.addCookie(accessTokenCookie);

        DefaultExpiringOAuth2RefreshToken refreshToken = (DefaultExpiringOAuth2RefreshToken) defaultOAuth2AccessToken
                .getRefreshToken();
        String refreshTokenValue = refreshToken.getValue();
        String[] refreshTokenParts = refreshTokenValue.split("\\.");
        // JWT payload only
        defaultOAuth2AccessToken.setRefreshToken(
                new DefaultExpiringOAuth2RefreshToken(refreshTokenParts[1], refreshToken.getExpiration()));
        // JWT header.signature
        Cookie refreshTokenCookie = new Cookie(OAuth2AccessToken.REFRESH_TOKEN,
                refreshTokenParts[0] + "." + refreshTokenParts[2]);
        refreshTokenCookie.setMaxAge(-1);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        httpServletResponse.addCookie(refreshTokenCookie);
    }

    public void clearCookies(HttpServletResponse httpServletResponse) {
        // JWT header.signature
        Cookie accessTokenCookie = new Cookie(OAuth2AccessToken.ACCESS_TOKEN, null);
        accessTokenCookie.setMaxAge(-1);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        httpServletResponse.addCookie(accessTokenCookie);

        Cookie refreshTokenCookie = new Cookie(OAuth2AccessToken.REFRESH_TOKEN, null);
        refreshTokenCookie.setMaxAge(-1);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        httpServletResponse.addCookie(refreshTokenCookie);
    }
}
