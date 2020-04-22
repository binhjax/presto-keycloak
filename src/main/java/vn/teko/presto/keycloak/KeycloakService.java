package vn.teko.presto.keycloak;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;

public class KeycloakService {

    static Keycloak keycloak = null;
    final static String serverUrl = "http://localhost:8180/auth";
    final static String realm = "spring-boot-quickstart";
    final static String clientId = "app-authz-rest-employee";
    final static String clientSecret = "secret";

    public KeycloakService() {
    }

    public static Keycloak getInstance(){
        if(keycloak == null){
        keycloak = KeycloakBuilder.builder() //
                .serverUrl(serverUrl) //
                .realm(realm) //
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS) //
                .clientId(clientId) //
                .clientSecret(clientSecret) //
                .build();
        }
        return keycloak;
    }
}
