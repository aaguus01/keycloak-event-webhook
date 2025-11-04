package com.paddlehub.security;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.jboss.logging.Logger;


/**
 * Listener that intercepts IDP registration events (e.g. Google sign-in)
 * and sends user data (including Keycloak ID) to a backend service secured with Basic Auth.
 */
public class IdpEventListenerProvider implements EventListenerProvider {

    private static final Logger log = Logger.getLogger(IdpEventListenerProvider.class);

    private final KeycloakSession session;
    private final String basicAuthHeader;
    private final String syncUrl;

    public IdpEventListenerProvider(KeycloakSession session) {
        String syncUrl = System.getenv("SYNC_URL");
        String username = System.getenv("SYNC_USER");
        String password = System.getenv("SYNC_PASS");

        // Fallback para tests o configuraciones locales
        if (syncUrl == null) syncUrl = System.getProperty("SYNC_URL");
        if (username == null) username = System.getProperty("SYNC_USER");
        if (password == null) password = System.getProperty("SYNC_PASS");

        if (syncUrl == null || username == null || password == null) {
            log.error("[IdpEventListener] Missing SYNC_URL / SYNC_USER / SYNC_PASS environment variables.");
            throw new RuntimeException("Missing environment variables for sync configuration");
        }

        String credentials = username + ":" + password;

        this.basicAuthHeader = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        this.syncUrl = syncUrl;
        this.session = session;

        log.infof("[IdpEventListener] Initialized with sync URL: %s", syncUrl);
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() == EventType.IDENTITY_PROVIDER_FIRST_LOGIN || event.getType() == EventType.REGISTER) {
            try {
                String userId = event.getUserId();
                UserModel user = session.users().getUserById(session.getContext().getRealm(), userId);

                if (user == null) {
                    log.warnf("[IdpEventListener] User not found for event type: %s", event.getType());
                    return;
                }

                String json = buildUserJson(user, userId);
                log.debugf("[IdpEventListener] Preparing to sync user %s (%s)", user.getUsername(), userId);

                sendToBackend(json);

            } catch (Exception e) {
                log.error("[IdpEventListener] Exception while processing IDP event", e);
            }
        }
    }

    private String buildUserJson(UserModel user, String userId) {
        String email = safe(user.getEmail());
        String username = safe(user.getUsername());
        String firstName = safe(user.getFirstName());
        String lastName = safe(user.getLastName());

        return String.format(
                "{" +
                        "\"keycloak_id\": \"%s\", " +
                        "\"username\": \"%s\", " +
                        "\"email\": \"%s\", " +
                        "\"first_name\": \"%s\", " +
                        "\"last_name\": \"%s\"" +
                        "}",
                userId, username, email, firstName, lastName
        );
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        // Reserved for future use (e.g., admin-created users)
        log.trace("[IdpEventListener] Ignoring AdminEvent: " + adminEvent.getOperationType());
    }

    /**
     * Sends JSON user data to the configured backend API via POST with Basic Auth.
     */
    protected void sendToBackend(String jsonBody) {
        try {
            URL url = new URL(syncUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Authorization", basicAuthHeader);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = conn.getResponseCode();
            if (responseCode >= 200 && responseCode < 300) {
                log.infof("[IdpEventListener] Successfully synced user to backend (HTTP %d)", responseCode);
            } else {
                log.warnf("[IdpEventListener] Backend responded with non-2xx code: %d", responseCode);
            }

            conn.disconnect();

        } catch (Exception e) {
            log.error("[IdpEventListener] Error sending data to backend", e);
        }
    }

    private String safe(String value) {
        return value != null ? value.replace("\"", "\\\"") : "";
    }

    @Override
    public void close() {
        log.trace("[IdpEventListener] Closing listener provider.");
    }
}