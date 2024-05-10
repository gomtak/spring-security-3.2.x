package com.whoflex.security.oauth2;

import com.whoflex.security.Account;
import com.whoflex.security.AccountRepository;
import com.whoflex.security.CustomUserDetails;
import com.whoflex.security.RoleType;
import com.whoflex.security.oauth2.OAuth2UserInfo;
import com.whoflex.security.oauth2.OAuth2UserInfoFactory;
import com.whoflex.security.oauth2.ProviderType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final AccountRepository accountRepository;
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User user = super.loadUser(userRequest);
        log.info("인증유저" + user);
        log.info("***********useRequest********");
        log.info(String.valueOf(userRequest));
        log.info("clientRegistration : " + userRequest.getClientRegistration().getClientName());
        log.info("clientRegistration : " + userRequest.getClientRegistration().getClientId());
        log.info("accestoken : " + userRequest.getAccessToken().getTokenValue());
        log.info("additionaparameter : " + userRequest.getAdditionalParameters());
        log.info("***********END********");
        try {
            return this.process(userRequest, user);
        } catch (Exception ex) {
            log.error(ex.getMessage());
            throw new OAuth2AuthenticationException(ex.getMessage());
        }
    }

    private OAuth2User process(OAuth2UserRequest userRequest, OAuth2User user) {
        ProviderType providerType =
                ProviderType.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());

        OAuth2UserInfo userInfo =
                OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, user.getAttributes());
        Account account =
                accountRepository
                        .findByName(userInfo.getEmail())
                        .orElseGet(() -> createAccount(userInfo, providerType));

        return CustomUserDetails.builder()
                .password(null)
                .roleType(account.getRoleType())
                .roleType(RoleType.USER)
                .build();
    }

    private Account createAccount(OAuth2UserInfo userInfo, ProviderType providerType) {
        return accountRepository.save(new Account(userInfo.getName(), null, RoleType.USER, providerType));
    }
}
