package vn.teko.presto.keycloak;

import com.google.common.collect.ImmutableList;
import io.prestosql.spi.Plugin;
import io.prestosql.spi.security.SystemAccessControlFactory;
import io.prestosql.spi.security.PasswordAuthenticatorFactory;

import java.util.ArrayList;

public class PrestoKeycloakPlugin
        implements Plugin
{
    @Override
    public Iterable<SystemAccessControlFactory> getSystemAccessControlFactories()
    {
        // ArrayList<SystemAccessControlFactory> list = new ArrayList<>();
        // SystemAccessControlFactory factory = new KeycloakSystemAccessControlFactory();
        // list.add(factory);
        // return list;
        return ImmutableList.of(new KeycloakSystemAccessControlFactory());
    }

    @Override
    public Iterable<PasswordAuthenticatorFactory> getPasswordAuthenticatorFactories()
    {
        return ImmutableList.<PasswordAuthenticatorFactory>builder()
                .add(new KeycloakAuthenticatorFactory())
                .build();
    }
}
