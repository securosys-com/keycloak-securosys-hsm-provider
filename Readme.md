# Keycloak Securosys HSM Provider

Keycloak Securosys HSM Provider is provider for Keycloak, that allows to use HSM keys to sign JWT tokens.
Signing operations runs externally on HSM, verify operations runs natively on Keycloak using provided public key 

Plugin support for now:
- JWT sign SHA256withRSA
- JWT sign SHA256withECDSA
- SAML sign SHA256withRSA
- HSM connection using Securosys JCE
- HSM connection using Securosys TSB REST API

>**NOTE** - SAML sign **SHA256withECDSA** is implemented, but for now is not supported by Keycloak.
> So it cannot be tested properly

## Prerequisites

You need:
- [Docker](https://docs.docker.com/engine/install/) or Keycloak instance
- Java installed
## Build

```sh
  ./gradlew clean providerDist -x test
```
The build creates a provider distribution in **build/provider-dist**:
- **build/provider-dist/provider** - Keycloak Securosys HSM provider jar
- **build/provider-dist/lib** - runtime dependency jars, for example **primus-jce**

>**Note** - task **providerDist** is also executed by **build** and **test**.

## Installing procedure
All jars from **build/provider-dist/provider** and **build/provider-dist/lib** have to be copied into the same
Keycloak **providers** directory. Do not keep the **provider** and **lib** subdirectories in Keycloak.

Example target layout:
```text
/opt/keycloak/providers/keycloak-securosys-hsm-provider-1.0.0.jar
/opt/keycloak/providers/primus-jce-2.5.4.jar
/opt/keycloak/providers/...
```

Keycloak automatically recognizes the new provider and adds it to UI.

For the first time or update provider jar in logs will be visible similar lines:
```sh
keycloak-1  | Updating the configuration and installing your custom providers, if any. Please wait.
keycloak-1  | 2026-01-22 12:29:17,147 WARN  [org.key.services] (build-19) KC-SERVICES0047: RS256 (com.securosys.hsm.provider.signature.algorithm.RS256) is implementing the internal SPI signature. This SPI is internal and may change without notice
keycloak-1  | 2026-01-22 12:29:17,148 WARN  [org.key.services] (build-19) KC-SERVICES0047: ES256 (com.securosys.hsm.provider.signature.algorithm.ES256) is implementing the internal SPI signature. This SPI is internal and may change without notice
keycloak-1  | 2026-01-22 12:29:17,453 WARN  [org.key.services] (build-19) KC-SERVICES0047: securosys-hsm-jce (com.securosys.hsm.provider.key.SecurosysJceKeyProviderFactory) is implementing the internal SPI keys. This SPI is internal and may change without notice
keycloak-1  | 2026-01-22 12:29:17,454 WARN  [org.key.services] (build-19) KC-SERVICES0047: securosys-hsm-tsb (com.securosys.hsm.provider.key.SecurosysTsbKeyProviderFactory) is implementing the internal SPI keys. This SPI is internal and may change without notice

```
That means, provider is successfully added to Keycloak.

## Configuration
On the UI Select: **Realm settings**, and next click **Keys** tab.
Now below will be visible 2 tabs:
- **Keys list** - list with all available keys on Keycloak
- **Add providers** - Where is located all providers configurations

Click **Add providers** and then button **Add provider**.
On Popup, Securosys providers can be found:
- **securosys-hsm-jce** - connect directly to HSM using Securosys JCE
- **securosys-hsm-tsb** - connect to HSM through Securosys TSB REST API

### JCE connection

When using **securosys-hsm-jce**, following properties can be changed:
1) **Name** - name of configuration for provider
2) **Priority** - key priority for using it in JWT sign. Bigger value == Hightest priority
3) **Enabled** - Enable/Disable provider
4) **Active** - Enable/Disable signing using this provider
5) **HSM Host** - hsm url/ip
6) **HSM Port** - hsm port
7) **HSM User** - hsm user
8) **HSM Setup Password** - hsm setup password. Password will be used only once to get User Secret and store it in **HSM Secret Path**
9) **HSM Proxy User** and **HSM Proxy Password** - proxy configuration. If HSM is not under the proxy, then fill it empty. 
10) **HSM attestaion key** - Attestation key name on HSM partition
11) **HSM Secret Path** - Path to secret, where UserSecret will be stored. Example: **/opt/keycloak/providers/.secret**
12) **Connection timeout** - timeout for connection to HSM. Default 10000 ms = 10 s. 
13) **Key Label** - Key label from HSM, that will be used in Keycloak
14) **Key Password** - Password for the key. Fill empty if key does not have password
15) **Algorithm** - Choose RS256 or ES256. RS256 for RSA keys and ES256 for EC keys.

After save key will be visible on **Keys list** tab.

>**NOTE** - **Connection timeout** is necessary to change timeout lower as possible. If there is any problem with
> connection with HSM, then whole Keycloak UI will wait for response on HSM. To prevent error with connection timeout
> after error plugin will be automatically disable

### TSB connection

When using **securosys-hsm-tsb**, Keycloak connects to Securosys TSB over REST instead of using the local JCE provider.
Following properties can be changed:

1) **Name** - name of configuration for provider
2) **Priority** - key priority for using it in JWT sign. Bigger value == Hightest priority
3) **Enabled** - Enable/Disable provider
4) **Active** - Enable/Disable signing using this provider
5) **Algorithm** - Choose RS256 or ES256. RS256 for RSA keys and ES256 for EC keys.
6) **TSB URL** - base URL of the TSB service, for example **https://tsb.example.com**
7) **Authentication Method** - choose **NONE**, **TOKEN**, or **CERT**
8) **Bearer Token** - required when **Authentication Method** is **TOKEN**
9) **mTLS P12 Path** - required when **Authentication Method** is **CERT**
10) **mTLS P12 Password** - required when **Authentication Method** is **CERT**
11) **Key Operation API Key** - API key used for signing and other key operation calls
12) **Key Management API Key** - API key used for key attributes and key management calls
13) **Key Label** - key label from HSM/TSB, that will be used in Keycloak
14) **Key Password** - password for the key. Fill empty if key does not have password

Authentication requirements:
- If **Authentication Method** is **TOKEN**, fill **Bearer Token**.
- If **Authentication Method** is **CERT**, fill **mTLS P12 Path** and **mTLS P12 Password**.
- If **Authentication Method** is **NONE**, bearer token and mTLS fields can stay empty.

TSB signing uses **POST /v1/synchronousSign** and key attributes are loaded through the TSB key management API.


## Test
Test commands run Keycloak in Docker, copy all jars from **build/provider-dist/provider** and
**build/provider-dist/lib** into one flat container directory, **/opt/keycloak/providers**, configure the provider,
and test both algorithm signatures:
- JWT and SAML RS256
- JWT ES256
```sh
  ./gradlew clean test
```
