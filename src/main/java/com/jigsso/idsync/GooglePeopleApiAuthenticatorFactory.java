package com.jigsso.idsync;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

/**
 * Google People API Authenticator Factory
 * 
 * Keycloak SPI 등록을 위한 Factory 클래스
 */
public class GooglePeopleApiAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "google-people-api-authenticator";
    private static final String DISPLAY_TYPE = "Google People API Post Login";
    private static final String HELP_TEXT = "Google IDP 로그인 후 People API를 호출하는 Post Login Authenticator";

    @Override
    public String getDisplayType() {
        return DISPLAY_TYPE;
    }

    @Override
    public String getReferenceCategory() {
        return "post-login";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new GooglePeopleApiAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
        // 초기화 로직 없음
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post 초기화 로직 없음
    }

    @Override
    public void close() {
        // 리소스 정리 없음
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}