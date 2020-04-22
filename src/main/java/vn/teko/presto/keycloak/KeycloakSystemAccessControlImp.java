package vn.teko.presto.keycloak;

import io.prestosql.spi.connector.CatalogSchemaName;
import io.prestosql.spi.connector.CatalogSchemaTableName;
import io.prestosql.spi.connector.SchemaTableName;
import io.prestosql.spi.security.AccessDeniedException;
import io.prestosql.spi.security.Identity;
import io.prestosql.spi.security.SystemSecurityContext;
import io.prestosql.spi.security.PrestoPrincipal;
import io.prestosql.spi.security.Privilege;
import io.prestosql.spi.security.SystemAccessControl;
import org.apache.commons.lang3.StringUtils;

// import org.apache.hadoop.conf.Configuration;
// import org.apache.hadoop.security.UserGroupInformation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Locale.ENGLISH;

import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;

import java.util.HashMap;
import java.util.Map;


public class KeycloakSystemAccessControlImp
  implements SystemAccessControl {

  Configuration configuration ;
  AuthzClient authzClient;

  private static Logger LOG = LoggerFactory.getLogger(KeycloakSystemAccessControlImp.class);

  public KeycloakSystemAccessControlImp(KeycloakConfig config) {
    super();
    configuration = new Configuration();
    configuration.setAuthServerUrl(config.getServerUrl());
    configuration.setRealm(config.getRealm());
    configuration.setResource(config.getClientId());
    Map<String,Object> clientCredentials = new HashMap<String , Object>() {{
                                                put("secret",   config.getClientSecret());
                                            }};
    configuration.setCredentials(clientCredentials);
  }
  public AuthzClient getAuthzClient() {
     if ( authzClient == null ) {
          authzClient = AuthzClient.create(configuration);
     }
     return authzClient;
  }
  public String getAccessToken(SystemSecurityContext context) {
      String ret = "";
      Identity identity = context.getIdentity();
      String user = identity.getUser();
      // String principal = identity.getPrincipal();
      if (KeycloakAuthenticator.cache.containsKey(user)){
         ret = KeycloakAuthenticator.cache.get(user);
      }
      return ret;
  }

  private boolean checkPermission(KeycloakPrestoResource resource, SystemSecurityContext context, PrestoAccessType accessType) {
    boolean ret = false;

    AuthzClient authzClient = getAuthzClient();
    String accessToken = getAccessToken(context);
    String resourceId = resource.getResourceId();
    System.out.println("resourceId: " + resourceId);
    System.out.println("scope: " + accessType.toString());
    // LOG.info("==> KeycloakSystemAccessControl.checkPermission: Access Token " + accessToken);
    try {
        AuthorizationRequest request = new AuthorizationRequest();

        request.addPermission(resourceId, accessType.toString());

        AuthorizationResponse response =  authzClient.authorization(context.getIdentity().getUser(),accessToken).authorize(request);
        String rpt = response.getToken();
        System.out.println("rpt: " + rpt);
        // LOG.info("==> KeycloakSystemAccessControl.checkPermission: Authorization Token " + rpt);
        return true;
    } catch(Exception e) {
        System.out.println("failed access resource: " + resourceId + ", error: " + e.toString());
    }

    return ret;
  }

  @Override
  public void checkCanSetUser(Optional<Principal> principal, String userName) {
    if(LOG.isDebugEnabled()) {
      LOG.debug("==> KeycloakSystemAccessControl.checkCanSetUser(" + userName + ")");
    }
    // if (!principal.isPresent()) {
    //   AccessDeniedException.denySetUser(principal, userName);
    // }
    // AccessDeniedException.denySetUser(principal, userName);
  }

  @Override
  public void checkCanSetSystemSessionProperty(SystemSecurityContext context, String propertyName) {
    if (!checkPermission(new KeycloakPrestoResource(), context, PrestoAccessType.ADMIN)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanSetSystemSessionProperty denied");
      AccessDeniedException.denySetSystemSessionProperty(propertyName);
    }
  }

  @Override
  public void checkCanAccessCatalog(SystemSecurityContext context, String catalogName) {
    if (!checkPermission(createResource(catalogName), context, PrestoAccessType.SELECT)) {
      AccessDeniedException.denyCatalogAccess(catalogName);
    }
  }

  @Override
  public Set<String> filterCatalogs(SystemSecurityContext context, Set<String> catalogs) {
    return catalogs;
  }

  @Override
  public void checkCanCreateSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    if (!checkPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context, PrestoAccessType.CREATE)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanCreateSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyCreateSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanDropSchema(SystemSecurityContext context, CatalogSchemaName schema) {
    if (!checkPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context, PrestoAccessType.DROP)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanDropSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyDropSchema(schema.getSchemaName());
    }
  }

  @Override
  public void checkCanRenameSchema(SystemSecurityContext context, CatalogSchemaName schema, String newSchemaName) {
    KeycloakPrestoResource res = createResource(schema.getCatalogName(), schema.getSchemaName());
    if (!checkPermission(res, context, PrestoAccessType.ALTER)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanRenameSchema(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyRenameSchema(schema.getSchemaName(), newSchemaName);
    }
  }

  @Override
  public void checkCanShowSchemas(SystemSecurityContext context, String catalogName) {
    if (!checkPermission(createResource(catalogName), context, PrestoAccessType.SELECT)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanShowSchemas(" + catalogName + ") denied");
      AccessDeniedException.denyShowSchemas(catalogName);
    }
  }

  @Override
  public Set<String> filterSchemas(SystemSecurityContext context, String catalogName, Set<String> schemaNames) {
    LOG.debug("==> KeycloakSystemAccessControl.filterSchemas(" + catalogName + ")");
    return schemaNames;
  }

  @Override
  public void checkCanCreateTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    if (!checkPermission(createResource(table), context, PrestoAccessType.CREATE)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanCreateTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    if (!checkPermission(createResource(table), context, PrestoAccessType.DROP)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanDropTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameTable(SystemSecurityContext context, CatalogSchemaTableName table, CatalogSchemaTableName newTable) {
    KeycloakPrestoResource res = createResource(table);
    if (!checkPermission(res, context, PrestoAccessType.ALTER)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanRenameTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameTable(table.getSchemaTableName().getTableName(), newTable.getSchemaTableName().getTableName());
    }
  }

  // @Override
  public void checkCanShowTablesMetadata(SystemSecurityContext context, CatalogSchemaName schema) {
    if (!checkPermission(createResource(schema.getCatalogName(), schema.getSchemaName()), context, PrestoAccessType.SELECT)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanShowTablesMetadata(" + schema.getSchemaName() + ") denied");
      AccessDeniedException.denyShowTablesMetadata(schema.getSchemaName());
    }
  }

  @Override
  public Set<SchemaTableName> filterTables(SystemSecurityContext context, String catalogName, Set<SchemaTableName> tableNames) {
    LOG.debug("==> KeycloakSystemAccessControl.filterTables(" + catalogName + ")");
    return tableNames;
  }

  @Override
  public void checkCanAddColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    KeycloakPrestoResource res = createResource(table);
    if (!checkPermission(res, context, PrestoAccessType.ALTER)) {
      AccessDeniedException.denyAddColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    KeycloakPrestoResource res = createResource(table);
    if (!checkPermission(res, context, PrestoAccessType.ALTER)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanDropColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDropColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanRenameColumn(SystemSecurityContext context, CatalogSchemaTableName table) {
    KeycloakPrestoResource res = createResource(table);
    if (!checkPermission(res, context, PrestoAccessType.ALTER)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanRenameColumn(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyRenameColumn(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    for (KeycloakPrestoResource res : createResource(table, columns)) {
      if (!checkPermission(res, context, PrestoAccessType.SELECT)) {
        LOG.info("==> KeycloakSystemAccessControl.checkCanSelectFromColumns(" + table.getSchemaTableName().getTableName() + ") denied");
        AccessDeniedException.denySelectColumns(table.getSchemaTableName().getTableName(), columns);
      }
    }
  }

  @Override
  public void checkCanInsertIntoTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    KeycloakPrestoResource res = createResource(table);
    if (!checkPermission(res, context, PrestoAccessType.INSERT)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanInsertIntoTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyInsertTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDeleteFromTable(SystemSecurityContext context, CatalogSchemaTableName table) {
    if (!checkPermission(createResource(table), context, PrestoAccessType.DELETE)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanDeleteFromTable(" + table.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyDeleteTable(table.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateView(SystemSecurityContext context, CatalogSchemaTableName view) {
    if (!checkPermission(createResource(view), context, PrestoAccessType.CREATE)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanCreateView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanDropView(SystemSecurityContext context, CatalogSchemaTableName view) {
    if (!checkPermission(createResource(view), context, PrestoAccessType.DROP)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanDropView(" + view.getSchemaTableName().getTableName() + ") denied");
      AccessDeniedException.denyCreateView(view.getSchemaTableName().getTableName());
    }
  }

  @Override
  public void checkCanCreateViewWithSelectFromColumns(SystemSecurityContext context, CatalogSchemaTableName table, Set<String> columns) {
    for (KeycloakPrestoResource res : createResource(table, columns)) {
      if (!checkPermission(res, context, PrestoAccessType.CREATE)) {
        LOG.info("==> KeycloakSystemAccessControl.checkCanDropView(" + table.getSchemaTableName().getTableName() + ") denied");
        AccessDeniedException.denyCreateViewWithSelect(table.getSchemaTableName().getTableName(), context.getIdentity());
      }
    }
  }

  @Override
  public void checkCanSetCatalogSessionProperty(SystemSecurityContext context, String catalogName, String propertyName) {
    if (!checkPermission(createResource(catalogName), context, PrestoAccessType.ADMIN)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanSetSystemSessionProperty(" + catalogName + ") denied");
      AccessDeniedException.denySetCatalogSessionProperty(catalogName, propertyName);
    }
  }

  @Override
  public void checkCanGrantTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal grantee, boolean withGrantOption) {
    if (!checkPermission(createResource(table), context, PrestoAccessType.ADMIN)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanGrantTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyGrantTablePrivilege(privilege.toString(), table.toString());
    }
  }

  @Override
  public void checkCanRevokeTablePrivilege(SystemSecurityContext context, Privilege privilege, CatalogSchemaTableName table, PrestoPrincipal revokee, boolean grantOptionFor) {
    if (!checkPermission(createResource(table), context, PrestoAccessType.ADMIN)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanRevokeTablePrivilege(" + table + ") denied");
      AccessDeniedException.denyRevokeTablePrivilege(privilege.toString(), table.toString());
    }
  }

  @Override
  public void checkCanShowRoles(SystemSecurityContext context, String catalogName) {
    if (!checkPermission(createResource(catalogName), context, PrestoAccessType.ADMIN)) {
      LOG.info("==> KeycloakSystemAccessControl.checkCanShowRoles(" + catalogName + ") denied");
      AccessDeniedException.denyShowRoles(catalogName);
    }
  }


  // Convert Presto Type into KeyCloak Type
  private static KeycloakPrestoResource createResource(CatalogSchemaName catalogSchemaName) {
    return createResource(catalogSchemaName.getCatalogName(), catalogSchemaName.getSchemaName());
  }

  private static KeycloakPrestoResource createResource(CatalogSchemaTableName catalogSchemaTableName) {
    return createResource(catalogSchemaTableName.getCatalogName(),
      catalogSchemaTableName.getSchemaTableName().getSchemaName(),
      catalogSchemaTableName.getSchemaTableName().getTableName());
  }

  private static KeycloakPrestoResource createResource(String catalogName) {
    return new KeycloakPrestoResource(catalogName, Optional.empty(), Optional.empty());
  }

  private static KeycloakPrestoResource createResource(String catalogName, String schemaName) {
    return new KeycloakPrestoResource(catalogName, Optional.of(schemaName), Optional.empty());
  }

  private static KeycloakPrestoResource createResource(String catalogName, String schemaName, final String tableName) {
    return new KeycloakPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName));
  }

  private static KeycloakPrestoResource createResource(String catalogName, String schemaName, final String tableName, final Optional<String> column) {
    return new KeycloakPrestoResource(catalogName, Optional.of(schemaName), Optional.of(tableName), column);
  }

  private static List<KeycloakPrestoResource> createResource(CatalogSchemaTableName table, Set<String> columns) {
    List<KeycloakPrestoResource> colRequests = new ArrayList<>();

    if (columns.size() > 0) {
      for (String column : columns) {
        KeycloakPrestoResource KeycloakPrestoResource = createResource(table.getCatalogName(),
          table.getSchemaTableName().getSchemaName(),
          table.getSchemaTableName().getTableName(), Optional.of(column));
        colRequests.add(KeycloakPrestoResource);
      }
    } else {
      colRequests.add(createResource(table.getCatalogName(),
        table.getSchemaTableName().getSchemaName(),
        table.getSchemaTableName().getTableName(), Optional.empty()));
    }
    return colRequests;
  }
}

class KeycloakPrestoResource {
  public String k_catalog = "";
  public String k_schema = "";
  public String k_table = "";
  public String k_column = "";

  public KeycloakPrestoResource() {}

  public KeycloakPrestoResource(String catalogName, Optional<String> schema, Optional<String> table) {
    k_catalog = catalogName;
    if (schema.isPresent()) {
      k_schema = schema.get();
    }
    if (table.isPresent()) {
      k_table = table.get();
    }
  }

  public KeycloakPrestoResource(String catalogName, Optional<String> schema, Optional<String> table, Optional<String> column) {
    k_catalog = catalogName;
    if (schema.isPresent()) {
      k_schema = schema.get();
    }
    if (table.isPresent()) {
      k_table = table.get();
    }
    if (column.isPresent()) {
      k_column = column.get();
    }
  }

  public String getCatalog() {
    return k_catalog;
  }

  public String getTable() {
    return k_table;
  }

  public String getSchema() {
    return k_table;
  }

  public Optional<SchemaTableName> getSchemaTable() {
    final String schema = getSchema();
    if (StringUtils.isNotEmpty(schema)) {
      return Optional.of(new SchemaTableName(schema, Optional.ofNullable(getTable()).orElse("*")));
    }
    return Optional.empty();
  }
  public String getResourceId() {
    return k_catalog + "." + k_schema + "." + k_table;
  }
}
enum PrestoAccessType {
  CREATE, DROP, SELECT, INSERT, DELETE, USE, ALTER, ALL, ADMIN;
}
