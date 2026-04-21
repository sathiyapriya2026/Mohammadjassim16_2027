import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;
import java.util.Arrays;

public class SecurePasswordManager {
    private static HashMap<String, String> passwordStore = new HashMap<>();
    private static SecretKey secretKey;
    private static final String KEY_FILE =
            System.getProperty("user.home") + File.separator + "secret.key";

    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;
    private static void loadOrGenerateKey() throws Exception {
        File file = new File(KEY_FILE);

        if (file.exists()) {
            byte[] keyBytes = new byte[(int) file.length()];
            try (FileInputStream fis = new FileInputStream(file)) {
                fis.read(keyBytes);
            }
            secretKey = new SecretKeySpec(keyBytes, "AES");
        } else {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            secretKey = keyGen.generateKey();

            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(secretKey.getEncoded());
            }
        }
    }
    private static String encrypt(String password) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] encrypted = cipher.doFinal(password.getBytes());

        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }
    private static String decrypt(String encryptedPassword) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encryptedPassword);

        byte[] iv = Arrays.copyOfRange(combined, 0, IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(combined, IV_LENGTH, combined.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.println("Key file path: " + KEY_FILE); 
        loadOrGenerateKey();
        while (true) {
            System.out.println("\n=== Password Manager ===");
            System.out.println("1. Add Account");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Delete Account");
            System.out.println("4. Exit");

            int choice = sc.nextInt();
            sc.nextLine();

            if (choice == 1) {
                System.out.print("Enter account name: ");
                String account = sc.nextLine();

                if (passwordStore.containsKey(account)) {
                    System.out.println("Account already exists!");
                    continue;
                }

                System.out.print("Enter password: ");
                char[] passwordChars = sc.nextLine().toCharArray();

                String encrypted = encrypt(new String(passwordChars));
                passwordStore.put(account, encrypted);
                Arrays.fill(passwordChars, '\0'); 
                System.out.println("Account added successfully!");

            } else if (choice == 2) {
                System.out.print("Enter account name: ");
                String account = sc.nextLine();

                if (passwordStore.containsKey(account)) {
                    String decrypted = decrypt(passwordStore.get(account));
                    System.out.println("Password: " + decrypted);
                    decrypted = null; 
                } else {
                    System.out.println("Account not found!");
                }

            } else if (choice == 3) {
                System.out.print("Enter account name: ");
                String account = sc.nextLine();

                if (passwordStore.containsKey(account)) {
                    passwordStore.remove(account);
                    System.out.println("Account deleted!");
                } else {
                    System.out.println("Account not found!");
                }

            } else if (choice == 4) {
                System.out.println("Exiting...");
                break;
            } else {
                System.out.println("Invalid choice!");
            }
        }
    }
}
