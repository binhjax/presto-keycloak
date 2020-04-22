package vn.teko.presto.keycloak;

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;

public class KeycloakConfig {
  private String serverUrl;
  private String realm;
  private String clientId;
  private String clientSecret;

  public String getServerUrl() { return serverUrl; }

  @Config("keycloak.server-url")
  @ConfigDescription("server url of Keycloak srver ")
  @SuppressWarnings("unused")
  public KeycloakConfig setServerUrl(String url) {
    this.serverUrl = url;
    return this;
  }

  public String getRealm() { return realm; }

  @Config("keycloak.realm")
  @ConfigDescription("realm in Keycloak")
  @SuppressWarnings("unused")
  public KeycloakConfig setRealm(String realm) {
    this.realm = realm;
    return this;
  }

  public String getClientId() { return clientId; }

  @Config("keycloak.client-id")
  @ConfigDescription("client-id in Keycloak")
  @SuppressWarnings("unused")
  public KeycloakConfig setClientId(String clientId) {
    this.clientId = clientId;
    return this;
  }

  public String getClientSecret() { return clientSecret; }

  @Config("keycloak.client-secret")
  @ConfigDescription("secret of client in Keycloak")
  @SuppressWarnings("unused")
  public KeycloakConfig setClientSecret(String secret) {
    this.clientSecret = secret;
    return this;
  }
}
