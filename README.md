# presto-keycloak
##  Compile
 ./gradlew build


## Test connect to keycloak
./gradlew run


## Install in presto
1. Create folder presto-keycloak in $(PRESTO_HOME)/plugin
2. Copy file  build/libs/presto-keycloak.jar to $(PRESTO_HOME)/plugin
cp  build/libs/presto-keycloak.jar  $(PRESTO_HOME)/plugin
3. Copy dependencies files:
cp  lib/*  $(PRESTO_HOME)/plugin

## Add config file
2. Copy config files to presto config
cp  config/access-control.properties  $(PRESTO_HOME)/default/etc
cp  config/password-authenticator.properties  $(PRESTO_HOME)/default/etc

## Config keycloak
# Login with admin
# Select Import, import
 realm  => Import  file: realm-export .json
