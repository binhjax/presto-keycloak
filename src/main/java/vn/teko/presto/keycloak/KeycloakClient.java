package vn.teko.presto.keycloak;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;

import java.util.HashMap;
import java.util.Map;

public class KeycloakClient {
    public static void main(String[] args) {
        // System.out.println("1. Client get access token.");
        Configuration configuration = new Configuration();

        configuration.setAuthServerUrl("http://localhost:8180/auth");
        configuration.setRealm("spring-boot-quickstart");
        configuration.setResource("app-authz-rest-employee");
        Map<String,Object> clientCredentials = new HashMap<String , Object>() {{
                                                    put("secret",    "secret");
                                                }};
        configuration.setCredentials(clientCredentials);

        AuthzClient authzClient = AuthzClient.create(configuration);

        // System.out.println("2. Check user/password token.");
        String username = "alice";
        String password = "alice";
        String accessToken = authzClient.obtainAccessToken("alice", "alice").getToken();
        // System.out.println("accessToken:" + accessToken);

        // System.out.println("clientAccessToken: " + accessToken);
        AuthorizationRequest request = new AuthorizationRequest();
        String resourceId = "system.jdbc.tables";
        String scope = "SELECT";
        request.addPermission(resourceId,scope);

        try {
            AuthorizationResponse response =  authzClient.authorization(accessToken).authorize(request);
            String rpt = response.getToken();
            System.out.println("rpt: " + rpt);
        } catch(Exception e) {
          System.out.println("failed access resource: " + e.toString());
        }

    }
}
