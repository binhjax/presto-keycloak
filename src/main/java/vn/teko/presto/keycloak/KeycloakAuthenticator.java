package vn.teko.presto.keycloak;

import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.BasicPrincipal;
import io.prestosql.spi.security.PasswordAuthenticator;

import javax.inject.Inject;

import java.io.File;
import java.security.Principal;
import java.util.function.Supplier;

import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// import static com.google.common.base.Suppliers.memoizeWithExpiration;
// import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class KeycloakAuthenticator
        implements PasswordAuthenticator
{

    Configuration configuration ;
    AuthzClient authzClient;
    // private final Supplier<AccessTokenStore> accessTokenStoreSupplier;


    private static Logger LOG = LoggerFactory.getLogger(KeycloakAuthenticator.class);

    public static HashMap<String, String> cache ;

    @Inject
    public KeycloakAuthenticator(KeycloakConfig config)
    {
        LOG.info("==> KeycloakAuthenticator.construct(" + config.getServerUrl() + ")");
        LOG.info("==> KeycloakAuthenticator.construct(" + config.getRealm() + ")");
        LOG.info("==> KeycloakAuthenticator.construct(" + config.getClientId() + ")");
        LOG.info("==> KeycloakAuthenticator.construct(" + config.getClientSecret() + ")");

        configuration = new Configuration();
        configuration.setAuthServerUrl(config.getServerUrl());
        configuration.setRealm(config.getRealm());
        configuration.setResource(config.getClientId());
        Map<String,Object> clientCredentials = new HashMap<String , Object>() {{
                                                    put("secret",   config.getClientSecret());
                                                }};
        configuration.setCredentials(clientCredentials);

        cache =  new HashMap<String , String>();
        // File file = config.getPasswordFile();
        // int cacheMaxSize = config.getAuthTokenCacheMaxSize();
        // accessTokenStoreSupplier = memoizeWithExpiration(
        //         () -> new AccessTokenStore(file, cacheMaxSize),
        //         config.getRefreshPeriod().toMillis(),
        //         MILLISECONDS);


    }
    public AuthzClient getAuthzClient() {
       if ( authzClient == null ) {
            authzClient = AuthzClient.create(configuration);
       }
       return authzClient;
    }
    public String getAccessToken(String user, String password) {

        if (cache.containsKey(user)) {
          return cache.get(user);
        }
        AuthzClient authzClient = getAuthzClient();

        String accessToken = "";
        try {
           accessToken = authzClient.obtainAccessToken(user, password).getToken();
           cache.put(user,password);

        } catch(Exception ex) {
            System.out.println("Exception:" + ex.toString());
        }
        return accessToken;
    }
    @Override
    public Principal createAuthenticatedPrincipal(String user, String password)
    {
        String accessToken = getAccessToken(user, password);
        if ( !accessToken.equals( "")) {
            return new BasicPrincipal(user);
        }
        else {
           throw new AccessDeniedException("Invalid credentials: " + user + ", " + password + ", " + accessToken);
        }
    }
}
