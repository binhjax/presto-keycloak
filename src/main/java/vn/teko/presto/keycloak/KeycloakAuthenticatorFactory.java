package vn.teko.presto.keycloak;

import com.google.inject.Injector;
import com.google.inject.Scopes;
import io.airlift.bootstrap.Bootstrap;
import io.prestosql.spi.security.PasswordAuthenticator;
import io.prestosql.spi.security.PasswordAuthenticatorFactory;

import java.util.Map;

import static io.airlift.configuration.ConfigBinder.configBinder;

public class KeycloakAuthenticatorFactory
        implements PasswordAuthenticatorFactory
{
    @Override
    public String getName()
    {
        return "keycloak";
    }

    @Override
    public PasswordAuthenticator create(Map<String, String> config)
    {

        Bootstrap app = new Bootstrap(
          binder -> {
            configBinder(binder).bindConfig(KeycloakConfig.class);
            binder.bind(KeycloakAuthenticator.class).in(Scopes.SINGLETON);
          }
        );
        Injector injector = app
                .strictConfig()
                .doNotInitializeLogging()
                .setRequiredConfigurationProperties(config)
                .initialize();

        return injector.getInstance(KeycloakAuthenticator.class);
    }
}
