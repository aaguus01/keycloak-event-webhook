package com.paddlehub.security;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class IdpEventListenerProviderFactory implements EventListenerProviderFactory {

    public static final String PROVIDER_ID = "idp-event-listener";

    @Override
    public EventListenerProvider create(KeycloakSession keycloakSession) {
        return new IdpEventListenerProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {
        //no necessary new implementation
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        //no necessary new implementation
    }

    @Override
    public void close() {
        //no necessary new implementation
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}