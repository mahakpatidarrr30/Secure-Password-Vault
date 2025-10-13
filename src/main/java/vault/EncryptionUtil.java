package vault;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class EncryptionUtil {

    private static SecretKeySpec getKey(String masterPassword) throws Exception {
        // AES key = first 32 bytes of SHA-256 hash of master password
        String keyStr = HashUtil.sha256(masterPassword).substring(0, 32);
        return new SecretKeySpec(keyStr.getBytes(), "AES");
    }

    public static String encrypt(String data, String masterPassword) throws Exception {
        SecretKeySpec secretKey = getKey(masterPassword);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
    }

    public static String decrypt(String encrypted, String masterPassword) throws Exception {
        SecretKeySpec secretKey = getKey(masterPassword);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)));
    }
}
