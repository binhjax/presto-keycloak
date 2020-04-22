package vn.teko.presto.keycloak;

import com.google.inject.Injector;
import com.google.inject.Scopes;
import io.airlift.bootstrap.Bootstrap;
import io.prestosql.spi.security.SystemAccessControl;
import io.prestosql.spi.security.SystemAccessControlFactory;

import java.util.Map;

import static com.google.common.base.Throwables.throwIfUnchecked;
import static io.airlift.configuration.ConfigBinder.configBinder;
import static java.util.Objects.requireNonNull;

public class KeycloakSystemAccessControlFactory
  implements SystemAccessControlFactory {
  private static final String NAME = "keycloak";

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public SystemAccessControl create(Map<String, String> config) {
    requireNonNull(config, "config is null");

    try {
      Bootstrap app = new Bootstrap(
        binder -> {
          configBinder(binder).bindConfig(KeycloakConfig.class);
          binder.bind(KeycloakSystemAccessControl.class).in(Scopes.SINGLETON);
        }
      );

      Injector injector = app
        .strictConfig()
        .doNotInitializeLogging()
        .setRequiredConfigurationProperties(config)
        .initialize();

      return injector.getInstance(KeycloakSystemAccessControl.class);
    } catch (Exception e) {
      throwIfUnchecked(e);
      throw new RuntimeException(e);
    }
  }
}
