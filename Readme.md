# Keycloak Securosys HSM Provider

Keycloak Securosys HSM Provider is provider for Keycloak, that allows to use HSM keys to sign JWT tokens.
Signing operations runs externally on HSM, verify operations runs natively on Keycloak using provided public key 

Plugin support for now:
- JWT sign SHA256withRSA
- JWT sign SHA256withECDSA
- SAML sign SHA256withRSA

>**NOTE** - SAML sign **SHA256withECDSA** is implemented, but for now is not supported by Keycloak.
> So it cannot be tested properly

## Prerequisites

You need:
- [Docker](https://docs.docker.com/engine/install/) or Keycloak instance
- Java installed
## Build

```sh
  ./gradlew clean shadowJar
```
>**Note** - task **shadowJar** builds provider with all necessary library like: **primus-jce** etc.

## Installing procedure
Built jar have to be copied to **providers** directory in keycloak. Keycloak automatically recognize new provider,
and adds it to UI.

For the first time or update provider jar in logs will be visible similar lines:
```sh
keycloak-1  | Updating the configuration and installing your custom providers, if any. Please wait.
keycloak-1  | 2026-01-22 12:29:17,147 WARN  [org.key.services] (build-19) KC-SERVICES0047: RS256 (com.securosys.hsm.provider.signature.algorithm.RS256) is implementing the internal SPI signature. This SPI is internal and may change without notice
keycloak-1  | 2026-01-22 12:29:17,148 WARN  [org.key.services] (build-19) KC-SERVICES0047: ES256 (com.securosys.hsm.provider.signature.algorithm.ES256) is implementing the internal SPI signature. This SPI is internal and may change without notice
keycloak-1  | 2026-01-22 12:29:17,453 WARN  [org.key.services] (build-19) KC-SERVICES0047: securosys-hsm (com.securosys.hsm.provider.key.SecurosysKeyProviderFactory) is implementing the internal SPI keys. This SPI is internal and may change without notice

```
That means, provider is successfully added to Keycloak.

## Configuration
On the UI Select: **Realm settings**, and next click **Keys** tab.
Now below will be visible 2 tabs:
- **Keys list** - list with all available keys on Keycloak
- **Add providers** - Where is located all providers configurations

Click **Add providers** and then button **Add provider**
On Popup, securosys-hsm provider can be found.
In Add provider form, following properties can be changed:
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


## Test
Test commands runs Keycloak in Docker, install provider, configure it and tests both algorithm signature:
- JWT and SAML RS256
- JWT ES256
```sh
  ./gradlew clean test
```
>**Note** - task shadowJar builds provider with all necessary library like: **primus-jce** etc.