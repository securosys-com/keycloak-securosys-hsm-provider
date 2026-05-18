# Keycloak Securosys HSM Provider

The Keycloak Securosys HSM Provider enables Keycloak to sign JWT tokens and SAML assertions with keys backed by an HSM.
Signing operations runs inside the HSM, verify operations run on Keycloak using the exported public key.

The plugin supports the following features:

- JWT sign SHA256withRSA
- JWT sign SHA256withECDSA
- SAML sign SHA256withRSA

> [!NOTE]
> SAML sign **SHA256withECDSA** is implemented, but for now is not supported by Keycloak.
> So it cannot be tested properly

## Documentation

The documentation is located at <https://docs.securosys.com/keycloak/overview>.

## Prerequisites

You need:

- A Keycloak instance
- Access credentials to a Securosys HSM (partion name, setup password, ...)
- Java Development Kit (JDK)

## Build

```sh
./gradlew clean shadowJar -x test
```

This builds the provider into a single "fat" JAR that includes all of its runtime dependencies.
The resulting JAR is located in the `build/libs/` directory.

## Install

To install the provider, simply copy the JAR from `buid/libs/`
to [Keycloak's `providers` directory](https://www.keycloak.org/server/directory-structure).
Inside a container-based installation, this directory is at `/opt/keycloak/providers/`.

Keycloak should automatically recognize the new provider and
make it available in the UI (Realm Settings > Keys > Providers).

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
10) **HSM attestation key** - Attestation key name on HSM partition
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

```sh
./gradlew clean test
```

This commands builds the provider, launches a Docker container with Keycloak, installs and configures the provider,
and finally runs the testsuite.

## License

This software is licensed under the [Apache 2.0 license](LICENSE).
