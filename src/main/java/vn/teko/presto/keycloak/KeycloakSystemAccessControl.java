package vn.teko.presto.keycloak;

import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.Identity;
import io.prestosql.spi.security.SystemSecurityContext;
import io.prestosql.spi.security.SystemAccessControl;

// import javax.inject.Inject;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeycloakSystemAccessControl
  implements SystemAccessControl {

    final private SystemAccessControl systemAccessControlImpl;
    private static Logger LOG = LoggerFactory.getLogger(KeycloakSystemAccessControl.class);

    @Inject
    public KeycloakSystemAccessControl(KeycloakConfig config) {
      SystemAccessControl impl = new KeycloakSystemAccessControlImp(config);
      systemAccessControlImpl = impl;
    }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    try {
      systemAccessControlImpl.checkCanSetUser(principal, userName);
    } catch (AccessDeniedException e) {
      throw e;
    } catch (Exception e) {
      AccessDeniedException.denySetUser(principal, userName);
    }
  }

  @Override
  public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName) {
    try {
      systemAccessControlImpl.checkCanSetSystemSessionProperty(context, propertyName);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName) {
    try {

      systemAccessControlImpl.checkCanAccessCatalog(context, catalogName);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyCatalogAccess(catalogName);
    }
  }

  @Override
  public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
    return catalogs;
  }

  @Override
  public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    try {

      systemAccessControlImpl.checkCanCreateSchema(context, schema);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    try {

      systemAccessControlImpl.checkCanDropSchema(context, schema);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName) {
    try {

      systemAccessControlImpl.checkCanRenameSchema(context, schema, newSchemaName);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }
  }

  @Override
  public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
    try {

      systemAccessControlImpl.checkCanShowSchemas(context, catalogName);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyShowSchemas();
    }
  }

  @Override
  public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
    return schemaNames;
  }

  @Override
  public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {

      systemAccessControlImpl.checkCanCreateTable(context, table);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {

      systemAccessControlImpl.checkCanDropTable(context, table);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    try {

      systemAccessControlImpl.checkCanRenameTable(context, table, newTable);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }
  }

  // @Override
  // public void checkCanShowTablesMetadata(SystemSecurityContext context, CatalogSchemaName schema) {
  //   try {
  //
  //     systemAccessControlImpl.checkCanShowTablesMetadata(context, schema);
  //   } catch (AccessDeniedException e) {
  //
  //     throw e;
  //   } catch (Exception e) {
  //
  //     AccessDeniedException.denyShowTablesMetadata(schema.getSchemaName());
  //   }
  // }

  @Override
  public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames) {
    return tableNames;
  }

  @Override
  public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {

      systemAccessControlImpl.checkCanAddColumn(context, table);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {

      systemAccessControlImpl.checkCanDropColumn(context, table);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {

      systemAccessControlImpl.checkCanRenameColumn(context, table);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      systemAccessControlImpl.checkCanSelectFromColumns(context, table, columns);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {
      AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
    }
  }

  @Override
  public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {

      systemAccessControlImpl.checkCanInsertIntoTable(context, table);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    try {

      systemAccessControlImpl.checkCanDeleteFromTable(context, table);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view) {
    try {

      systemAccessControlImpl.checkCanCreateView(context, view);
    } catch (AccessDeniedException e) {

      throw e;
    } catch (Exception e) {

      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view) {
    try {
      systemAccessControlImpl.checkCanDropView(context, view);
    } catch (AccessDeniedException e) {
      throw e;
    } catch (Exception e) {
      AccessDeniedException.denyDropView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    try {
      systemAccessControlImpl.checkCanCreateViewWithSelectFromColumns(context, table, columns);
    } catch (AccessDeniedException e) {
      throw e;
    } catch (Exception e) {
      AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), context.getIdentity());
    }
  }

  @Override
  public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName) {
    try {
      systemAccessControlImpl.checkCanSetCatalogSessionProperty(context, catalogName, propertyName);
    } catch (AccessDeniedException e) {
      throw e;
    } catch (Exception e) {
      AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
  }
}
