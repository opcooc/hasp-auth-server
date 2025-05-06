package org.hasp.server.utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Random;

public class KeyUtils {

    public static final String CURRENT_KID = "current_kid.txt";

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");
    private static final Random RANDOM = new Random();

    public static KeyPair generateRsaKeyPair() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    public static String generateKid() {
        String timestamp = LocalDateTime.now().format(FORMATTER);
        String random = Integer.toHexString(RANDOM.nextInt(0x10000)); // 4位随机hex
        return timestamp + "_" + random;
    }

    public static void generateAndSaveKeyPair(String dirPath) throws IOException {
        Files.createDirectories(Paths.get(dirPath));
        String kid = generateKid();
        KeyPair keyPair = generateRsaKeyPair();

        Path privatePath = Paths.get(dirPath, "jwt_private_" + kid + ".pem");
        Path publicPath = Paths.get(dirPath, "jwt_public_" + kid + ".pem");

        savePem(privatePath, "PRIVATE KEY", keyPair.getPrivate().getEncoded());
        savePem(publicPath, "PUBLIC KEY", keyPair.getPublic().getEncoded());

        // 更新 current_kid.txt
        Files.writeString(Paths.get(dirPath, CURRENT_KID), kid);
    }

    private static void savePem(Path path, String type, byte[] content) throws IOException {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(content);
        String pem = "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
        Files.writeString(path, pem);
    }

    public static String loadCurrentKid(String dir) throws IOException {
        Path kidPath = Paths.get(dir, CURRENT_KID);
        return Files.readString(kidPath).trim();
    }

    public static PrivateKey loadPrivateKeyByKid(String dir, String kid) throws Exception {
        return loadPrivateKey(Paths.get(dir, "jwt_private_" + kid + ".pem"));
    }

    public static PublicKey loadPublicKeyByKid(String dir, String kid) throws Exception {
        return loadPublicKey(Paths.get(dir, "jwt_public_" + kid + ".pem"));
    }

    public static PublicKey loadPublicKey(Path filePath) throws Exception {
        String pem = Files.readString(filePath);
        String base64 = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", ""); // 清除换行和空格
        byte[] decoded = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(Path filePath) throws Exception {
        String pem = Files.readString(filePath);
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

}
