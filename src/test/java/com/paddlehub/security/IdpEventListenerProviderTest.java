package com.paddlehub.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;


import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.mockito.Mockito.*;

class IdpEventListenerProviderTest {

    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private Event event;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        event = mock(Event.class);

        when(session.getContext()).thenReturn(mock(org.keycloak.models.KeycloakContext.class));
        when(session.getContext().getRealm()).thenReturn(realm);

        UserProvider userProvider = mock(UserProvider.class);
        when(session.users()).thenReturn(userProvider);
    }

    @Test
    void testOnEvent_sendsUserData() {
        System.setProperty("SYNC_URL", "http://localhost:8080/paddlehub/user-management/v1/users");
        System.setProperty("SYNC_USER", "listenerUser");
        System.setProperty("SYNC_PASS", "superSecret");

        when(event.getUserId()).thenReturn("abc-123");
        when(event.getType()).thenReturn(EventType.IDENTITY_PROVIDER_FIRST_LOGIN);
        when(session.users().getUserById(realm, "abc-123")).thenReturn(user);
        when(user.getUsername()).thenReturn("jdoe");
        when(user.getEmail()).thenReturn("john@example.com");
        when(user.getFirstName()).thenReturn("John");
        when(user.getLastName()).thenReturn("Doe");

        IdpEventListenerProvider provider = spy(new IdpEventListenerProvider(session));

        // Evita hacer peticiones HTTP reales
        doNothing().when(provider).sendToBackend(anyString());

        provider.onEvent(event);

        verify(session.users()).getUserById(realm, "abc-123");
        verify(provider).sendToBackend(anyString());
    }

    private static String getString(ByteArrayOutputStream out) {
        return out.toString();
    }
}