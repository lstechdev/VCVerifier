# VCBackend

VCBackend includes in a single binary demo versions of Issuer, Verifier and Wallet (same-device only, for a cross-device wallet please see [VCWallet](https://github.com/hesusruiz/VCWallet)).

This facilitates installation and allows to see how all components fit together and the protocol flows between them.

## Installation

Clone the repository:

```
git clone git@github.com:hesusruiz/VCBackend.git
```

Before running VCBackend you need to have accessible the endpoints implemented by [VCWaltid](https://github.com/FIWARE/VCWaltid). Please install an run VCWaltid following the instructions there. The endpoints and ports required from VCBackend are preconfigured to match the ones from VCWaltid without any change. If you do require changes, they can be setup in the configuration file in `configs\server.yaml`.

## Running

The first time that you start the VCBackend you have to make sure the database artifacts are consistent. Tou can use the provided Makefile for that or run the command directly:

```
make datamodel
```

The above command has to be executed every time that you modify the database model in the application.

To start VCBackend in development mode, type:

```
go run .
```

# Configuration

The configuration file in `config\server.yaml` provides for some configuration of VCBackend. An example config file is:

```yaml
server:
  listenAddress: "0.0.0.0:3000"
  staticDir: "back/www"
  templateDir: "back/views"
  environment: development
  loglevel: DEBUG

store:
  driverName: "sqlite3"
  dataSourceName: "file:issuer.sqlite?mode=rwc&cache=shared&_fk=1"

issuer:
  id: HappyPets
  name: HappyPets
  password: ThePassword
  store:
    driverName: "sqlite3"
    dataSourceName: "file:issuer.sqlite?mode=rwc&cache=shared&_fk=1"

verifier:
  id: PacketDelivery
  name: PacketDelivery
  password: ThePassword
  store:
    driverName: "sqlite3"
    dataSourceName: "file:verifier.sqlite?mode=rwc&cache=shared&_fk=1"
  protectedResource:
    url: "https://www.google.com"

verifiableregistry:
  password: ThePassword
  store:
    driverName: "sqlite3"
    dataSourceName: "file:verifiableregistry.sqlite?mode=rwc&cache=shared&_fk=1"

wallet:
  store:
    driverName: "sqlite3"
    dataSourceName: "file:wallet.sqlite?mode=rwc&cache=shared&_fk=1"

ssikit:
  coreURL: localhost:7000
  signatoryURL: http://localhost:7001
  auditorURL: localhost:7002
  custodianURL: localhost:7003
  essifURL: localhost:7010
```
