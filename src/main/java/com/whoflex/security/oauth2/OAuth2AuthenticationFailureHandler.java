package com.whoflex.security.oauth2;

import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    public OAuth2AuthenticationFailureHandler(OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository) {
    }
}
