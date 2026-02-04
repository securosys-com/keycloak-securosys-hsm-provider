/**
 * Copyright (c)2025 Securosys SA, authors: Tomasz Madej
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * <p>
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 **/
package com.securosys.hsm.util;

import com.securosys.hsm.exception.BusinessException;
import com.securosys.hsm.exception.BusinessReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class FileUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(FileUtil.class);


    public static Path createTemporaryFileWithRndName(String filename, String postfix, byte[] content) {
        try {
            Path tmpFile = Files.createTempFile(filename + OffsetDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss.N")), postfix);
            if (content != null)
                Files.write(tmpFile, content);
            return tmpFile.toAbsolutePath();
        } catch (IOException e) {
            String msg = "Failed to create or write to temporary file.";
            LOGGER.warn("An error occurred while attempting to create a temporary file or write content to it. Please check file permissions and ensure there is sufficient disk space.");
            throw new BusinessException(msg, BusinessReason.ERROR_IO, e);
        }
    }

    public static void addFileToZip(String fileName, Path filePath, ZipOutputStream zipOutputStream) throws IOException {
        // Create a new entry in the zip file
        ZipEntry zipEntry = new ZipEntry(fileName);
        zipOutputStream.putNextEntry(zipEntry);

        // Read the file content and write it to the zip output stream
        byte[] bytes = Files.readAllBytes(filePath);
        zipOutputStream.write(bytes, 0, bytes.length);

        // Close the zip entry
        zipOutputStream.closeEntry();
    }


    public static String fileToContentString(String filePath, boolean base64LineEncoding) {
        File file = new File(filePath);
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(file.getPath());
            StringBuilder stringBuilder = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(base64LineEncoding ? Base64.getEncoder().encodeToString(line.getBytes()) : line).append("\n");
            }
            return stringBuilder.toString();
        } catch (FileNotFoundException e) {
            String msg = "Content to File.";
            LOGGER.warn(msg);
            throw new BusinessException(msg, BusinessReason.ERROR_FILE_NOT_FOUND, e);
        } catch (IOException e) {
            String msg = "Could not read from file.";
            LOGGER.warn(msg);
            throw new BusinessException(msg, BusinessReason.ERROR_IO, e);
        } finally {
            if (file.exists()) file.delete();
        }
    }

    public static byte[] readFileToBytes(String filePath){
        try {
            return Files.readAllBytes(Path.of(filePath));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static void saveFile(byte[] file,String destinationPath){
        try {
            Path path = Path.of(destinationPath);
            // Ensure parent directories exist
            Files.createDirectories(path.getParent());

            // Write the file bytes to the destination
            try (FileOutputStream fos = new FileOutputStream(destinationPath)) {
                fos.write(file);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to save file: " + destinationPath, e);
        }
    }

    public static void deleteFileIfExists(String filePath) {
        File file = new File(filePath);
        if (file.exists()) file.delete();
    }
}
