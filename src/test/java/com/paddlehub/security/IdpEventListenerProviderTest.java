package com.paddlehub.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.AuthorizationContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import jakarta.ws.rs.core.HttpHeaders;

import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.urls.UrlType;
import org.mockito.Mockito;


import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.util.Locale;

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

        // 🔹 Crear un KeycloakContext manual sin usar Mockito
        KeycloakContext fakeContext = new KeycloakContext() {
            @Override public RealmModel getRealm() { return realm; }
            @Override public void setRealm(RealmModel realm) {}

            @Override
            public URI getAuthServerUrl() {
                return URI.create("http://localhost:8080/auth"); // valor ficticio
            }

            @Override
            public String getContextPath() {
                return "";
            }

            @Override
            public KeycloakUriInfo getUri() {
                return null;
            }

            @Override
            public KeycloakUriInfo getUri(UrlType urlType) {
                return null;
            }

            @Override
            public HttpHeaders getRequestHeaders() {
                return null;
            }

            @Override
            public ClientConnection getConnection() {
                return null;
            }

            @Override
            public void setConnection(ClientConnection clientConnection) {}

            @Override
            public void setHttpRequest(HttpRequest httpRequest) {

            }

            @Override
            public void setHttpResponse(HttpResponse httpResponse) {

            }

            @Override
            public ClientModel getClient() {
                return null;
            }

            @Override
            public void setClient(ClientModel client) {}

            @Override
            public Locale resolveLocale(UserModel userModel) {
                return Locale.ENGLISH;
            }

            @Override
            public AuthenticationSessionModel getAuthenticationSession() {
                return null;
            }

            @Override
            public void setAuthenticationSession(AuthenticationSessionModel authenticationSession) {}

            @Override
            public HttpRequest getHttpRequest() {
                return null;
            }

            @Override
            public HttpResponse getHttpResponse() {
                return null;
            }

            @Override
            public OrganizationModel getOrganization() {
                return null;
            }

            @Override
            public void setOrganization(OrganizationModel organizationModel) {}
        };

        when(session.getContext()).thenReturn(fakeContext);

        UserProvider userProvider = mock(UserProvider.class);
        when(session.users()).thenReturn(userProvider);
    }

    @Test
    void testOnEvent_sendsUserData() {
        // Mock de variables
        System.setProperty("SYNC_URL", "http://localhost:8080/paddlehub/user-management/v1/users");
        System.setProperty("SYNC_USER", "listenerUser");
        System.setProperty("SYNC_PASS", "superSecret");

        // Mock de datos
        when(event.getUserId()).thenReturn("abc-123");
        when(event.getType()).thenReturn(EventType.IDENTITY_PROVIDER_FIRST_LOGIN);
        when(session.users().getUserById(realm, "abc-123")).thenReturn(user);
        when(user.getUsername()).thenReturn("jdoe");
        when(user.getEmail()).thenReturn("john@example.com");
        when(user.getFirstName()).thenReturn("John");
        when(user.getLastName()).thenReturn("Doe");

        // Crear spy y mockear el envío HTTP
        IdpEventListenerProvider provider = Mockito.spy(new IdpEventListenerProvider(session));
        doNothing().when(provider).sendToBackend(anyString());

        // Ejecutar evento real
        provider.onEvent(event);

        // Verificar que el flujo se ejecutó
        verify(session.users()).getUserById(realm, "abc-123");
        verify(provider).sendToBackend(anyString());
    }
}