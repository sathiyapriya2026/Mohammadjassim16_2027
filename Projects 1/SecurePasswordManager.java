import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

public class SecurePasswordManager {

    private static HashMap<String, String> passwordStore = new HashMap<>();
    private static SecretKey secretKey;

    private static void generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        secretKey = keyGen.generateKey();
    }

    private static String encrypt(String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decrypt(String encryptedPassword) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decrypted);
    }
    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);
        generateKey();

        while (true) {
            System.out.println("\n=== Password Manager ===");
            System.out.println("1. Add Account");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Delete Account");
            System.out.println("4. Exit");

            int choice = sc.nextInt();
            sc.nextLine(); // consume newline

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
