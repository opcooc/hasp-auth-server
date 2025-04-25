package org.hasp.server.utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Random;

public class KeyUtils {

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

    public static void generateAndSaveKeyPair(String dir, String tenant) throws IOException {
        String dirPath = dir + "/" + tenant;
        Files.createDirectories(Paths.get(dirPath));
        String kid = generateKid();
        KeyPair keyPair = generateRsaKeyPair();

        Path privatePath = Paths.get(dirPath, "jwt_private_" + kid + ".pem");
        Path publicPath = Paths.get(dirPath, "jwt_public_" + kid + ".pem");

        savePem(privatePath, "PRIVATE KEY", keyPair.getPrivate().getEncoded());
        savePem(publicPath, "PUBLIC KEY", keyPair.getPublic().getEncoded());

        // 更新 current_kid.txt
        Files.writeString(Paths.get(dirPath, "current_kid.txt"), kid);

        // 覆盖 current 指针（使用硬复制或符号链接）
        Files.copy(privatePath, Paths.get(dirPath, "current_private.pem"), StandardCopyOption.REPLACE_EXISTING);
        Files.copy(publicPath, Paths.get(dirPath, "current_public.pem"), StandardCopyOption.REPLACE_EXISTING);
    }

    private static void savePem(Path path, String type, byte[] content) throws IOException {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(content);
        String pem = "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
        Files.writeString(path, pem);
    }

    public static String loadCurrentKid(String dir, String tenant) throws IOException {
        Path kidPath = Paths.get(dir, tenant, "current_kid.txt");
        return Files.readString(kidPath).trim();
    }

    public static PrivateKey loadCurrentPrivateKey(String dir, String tenant) throws Exception {
        return loadPrivateKey(Paths.get(dir, tenant, "current_private.pem"));
    }

    public static PrivateKey loadPrivateKeyByKid(String dir, String tenant, String kid) throws Exception {
        return loadPrivateKey(Paths.get(dir, tenant, "jwt_private_" + kid + ".pem"));
    }

    public static PublicKey loadCurrentPublicKey(String dir, String tenant) throws Exception {
        return loadPublicKey(Paths.get(dir, tenant, "current_public.pem"));
    }

    public static PublicKey loadPublicKeyByKid(String dir, String tenant, String kid) throws Exception {
        return loadPublicKey(Paths.get(dir, tenant, "jwt_public_" + kid + ".pem"));
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
