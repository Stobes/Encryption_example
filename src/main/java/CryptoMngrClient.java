import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.UUID;

public class CryptoMngrClient {
    private static int AES_128 = 128;
    public static void main(String[] args) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoMngr.ALGORITHM);
        keyGenerator.init(AES_128);
        //Generate Key
        SecretKey key = keyGenerator.generateKey();
        //Initialization vector
        SecretKey IV = keyGenerator.generateKey();
        String randomString = UUID.randomUUID().toString().substring(0, 16);
        System.out.println("1. Message to Encrypt: " + randomString);
        byte[] cipherText = CryptoMngr.encrypt(key.getEncoded(), IV.getEncoded(), randomString.getBytes());
        System.out.println("2. Encrypted Text: " + Base64.getEncoder().encodeToString(cipherText));
        byte[] decryptedString = CryptoMngr.decrypt(key.getEncoded(), IV.getEncoded(), cipherText);
        System.out.println("3. Decrypted Message : " + new String(decryptedString));
    }
}