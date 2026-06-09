package com.securosys.hsm;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class KeycloakTestContainers {

    private static final Path PROVIDER_DIST = Paths.get("build", "provider-dist");

    private KeycloakTestContainers() {
    }

    static GenericContainer<?> withProviderDist(GenericContainer<?> container) {
        if (!Files.isDirectory(PROVIDER_DIST)) {
            throw new IllegalStateException("Provider distribution not found: " + PROVIDER_DIST.toAbsolutePath());
        }

        try (Stream<Path> files = Files.walk(PROVIDER_DIST)) {
            List<Path> jars = files
                    .filter(Files::isRegularFile)
                    .filter(file -> file.getFileName().toString().endsWith(".jar"))
                    .sorted()
                    .collect(Collectors.toList());

            if (jars.isEmpty()) {
                throw new IllegalStateException("No provider jars found in: " + PROVIDER_DIST.toAbsolutePath());
            }

            // Keycloak loads provider jars from one flat providers directory.
            jars.forEach(jar -> container.withCopyFileToContainer(
                    MountableFile.forHostPath(jar.toString()),
                    "/opt/keycloak/providers/" + jar.getFileName()
            ));

            return container;
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read provider distribution: " + PROVIDER_DIST.toAbsolutePath(), e);
        }
    }
}
