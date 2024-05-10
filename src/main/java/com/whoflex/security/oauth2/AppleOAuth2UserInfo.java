package com.whoflex.security.oauth2;

import com.whoflex.security.oauth2.OAuth2UserInfo;

import java.util.Map;

public class AppleOAuth2UserInfo extends OAuth2UserInfo {
    public AppleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getGivenName() {
        return (String) attributes.get("given_name");
    }

    @Override
    public String getFamilyName() {
        return (String) attributes.get("family_name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("imageUrl");
    }

    @Override
    public boolean getEmailVerified() {
        return (boolean) attributes.get("email_verified");
    }
}
