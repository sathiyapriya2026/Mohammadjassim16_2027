import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;
import java.security.SecureRandom;

public class SecurePasswordManager {

    private static HashMap<String, String> passwordStore = new HashMap<>();
    private static SecretKey secretKey;

    private static final String MASTER_PASSWORD = "admin123";
    private static final int MAX_ATTEMPTS = 3;

    private static void generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        secretKey = keyGen.generateKey();
    }

    private static String encrypt(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(password.getBytes());

        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    private static String decrypt(String encryptedPassword) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] combined = Base64.getDecoder().decode(encryptedPassword);

        byte[] iv = new byte[16];
        byte[] encrypted = new byte[combined.length - 16];

        System.arraycopy(combined, 0, iv, 0, 16);
        System.arraycopy(combined, 16, encrypted, 0, encrypted.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        generateKey();

        int attempts = 0;
        boolean authenticated = false;

        while (attempts < MAX_ATTEMPTS) {
            System.out.print("Enter master password: ");
            String input = sc.nextLine();

            if (input.equals(MASTER_PASSWORD)) {
                authenticated = true;
                break;
            } else {
                attempts++;
                System.out.println("Wrong password! Attempts left: " + (MAX_ATTEMPTS - attempts));
            }
        }

        if (!authenticated) {
            System.out.println("Too many failed attempts. Exiting...");
            return;
        }

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
                System.out.print("Enter password: ");
                String password = sc.nextLine();

                String encrypted = encrypt(password);
                passwordStore.put(account, encrypted);
                System.out.println("Account added successfully!");

            } else if (choice == 2) {
                System.out.print("Enter account name: ");
                String account = sc.nextLine();

                if (passwordStore.containsKey(account)) {
                    String decrypted = decrypt(passwordStore.get(account));
                    System.out.println("Password: " + decrypted);
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
