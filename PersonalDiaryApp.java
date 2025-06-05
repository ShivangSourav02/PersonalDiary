// Main Application File: PersonalDiaryApp.java
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class User {
    private byte[] salt;
    private byte[] hashedPassword;

    public User(byte[] salt, byte[] hashedPassword) {
        this.salt = salt;
        this.hashedPassword = hashedPassword;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getHashedPassword() {
        return hashedPassword;
    }
}

class DiaryEntry {
    private String id; // Typically timestamp based
    private byte[] iv;
    private byte[] encryptedContent;

    // Constructor for loading
    public DiaryEntry(String id, byte[] iv, byte[] encryptedContent) {
        this.id = id;
        this.iv = iv;
        this.encryptedContent = encryptedContent;
    }

    public String getId() {
        return id;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getEncryptedContent() {
        return encryptedContent;
    }
}

class CryptoService {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding"; // CBC needs IV
    private static final int KEY_SIZE = 256; // bits
    private static final int SALT_SIZE = 16; // bytes
    private static final int IV_SIZE = 16; // bytes for AES/CBC
    private static final int ITERATION_COUNT = 65536;
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    }

    public static byte[] hashPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        return factory.generateSecret(spec).getEncoded();
    }

    public static SecretKey deriveKeyFromPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static byte[] encrypt(String plainText, SecretKey key, byte[] iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(plainText.getBytes());
    }

    public static String decrypt(byte[] cipherText, SecretKey key, byte[] iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return new String(cipher.doFinal(cipherText));
    }
}

class FileStorageService {
    private static final Path USER_DATA_PATH = Paths.get("userdata.dat");
    private static final Path ENTRIES_DIR_PATH = Paths.get("entries");
    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss-SSSSSS"); // For unique filenames

    public FileStorageService() {
        try {
            if (!Files.exists(ENTRIES_DIR_PATH)) {
                Files.createDirectories(ENTRIES_DIR_PATH);
            }
        } catch (IOException e) {
            System.err.println("Error creating entries directory: " + e.getMessage());
        }
    }

    public void saveUser(User user) throws IOException {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(USER_DATA_PATH.toFile()))) {
            oos.writeObject(user.getSalt());
            oos.writeObject(user.getHashedPassword());
        }
    }

    public User loadUser() throws IOException, ClassNotFoundException {
        if (!Files.exists(USER_DATA_PATH)) {
            return null;
        }
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(USER_DATA_PATH.toFile()))) {
            byte[] salt = (byte[]) ois.readObject();
            byte[] hashedPassword = (byte[]) ois.readObject();
            return new User(salt, hashedPassword);
        }
    }

    public String saveEntry(String content, SecretKey key) throws Exception {
        byte[] iv = CryptoService.generateIv();
        byte[] encryptedContent = CryptoService.encrypt(content, key, iv);
        String entryId = LocalDateTime.now().format(DATE_TIME_FORMATTER);
        Path entryPath = ENTRIES_DIR_PATH.resolve(entryId + ".entry");

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(entryPath.toFile()))) {
            oos.writeObject(iv);
            oos.writeObject(encryptedContent);
        }
        return entryId;
    }

    public DiaryEntry loadEntry(String entryId) throws IOException, ClassNotFoundException {
         Path entryPath = ENTRIES_DIR_PATH.resolve(entryId + ".entry");
         if (!Files.exists(entryPath)) return null;

        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(entryPath.toFile()))) {
            byte[] iv = (byte[]) ois.readObject();
            byte[] encryptedContent = (byte[]) ois.readObject();
            return new DiaryEntry(entryId, iv, encryptedContent);
        }
    }

    public List<String> listEntryIds() throws IOException {
        if (!Files.exists(ENTRIES_DIR_PATH) || !Files.isDirectory(ENTRIES_DIR_PATH)) {
            return Collections.emptyList();
        }
        try (Stream<Path> paths = Files.list(ENTRIES_DIR_PATH)) {
            return paths
                    .filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString().replace(".entry", ""))
                    .sorted(Comparator.reverseOrder()) // Show newest first
                    .collect(Collectors.toList());
        }
    }

    public boolean deleteEntry(String entryId) throws IOException {
        Path entryPath = ENTRIES_DIR_PATH.resolve(entryId + ".entry");
        return Files.deleteIfExists(entryPath);
    }
}

public class PersonalDiaryApp {
    private Scanner scanner;
    private FileStorageService storageService;
    private User currentUser;
    private SecretKey sessionKey; // Derived from password for the current session

    public PersonalDiaryApp() {
        this.scanner = new Scanner(System.in);
        this.storageService = new FileStorageService();
    }

    public static void main(String[] args) {
        PersonalDiaryApp app = new PersonalDiaryApp();
        app.start();
        app.scanner.close();
    }

    public void start() {
        System.out.println("🌟 Welcome to Your Personal Secure Diary 🌟");
        try {
            this.currentUser = storageService.loadUser();
            if (currentUser == null) {
                System.out.println("No user found. Please register.");
                registerUser();
            } else {
                loginUser();
            }

            if (sessionKey != null) { // Proceed only if login/registration was successful
                mainMenu();
            }

        } catch (Exception e) {
            System.err.println("🚨 Critical error during startup: " + e.getMessage());
            e.printStackTrace();
        }
        System.out.println("Thank you for using the Personal Secure Diary. Goodbye! 👋");
    }

    private void registerUser() throws Exception {
        System.out.print("Enter a new master password: ");
        String password = scanner.nextLine();
        System.out.print("Confirm master password: ");
        String confirmPassword = scanner.nextLine();

        if (!password.equals(confirmPassword)) {
            System.err.println("Passwords do not match. Please try again.");
            registerUser(); // Recursive call, could be improved with a loop
            return;
        }
        if (password.isEmpty()){
            System.err.println("Password cannot be empty. Please try again.");
            registerUser();
            return;
        }

        byte[] salt = CryptoService.generateSalt();
        byte[] hashedPassword = CryptoService.hashPassword(password, salt);
        currentUser = new User(salt, hashedPassword);
        storageService.saveUser(currentUser);
        sessionKey = CryptoService.deriveKeyFromPassword(password, salt); // Set session key
        System.out.println("✅ Registration successful! You are now logged in.");
    }

    private void loginUser() throws Exception {
        int attempts = 0;
        while (attempts < 3) {
            System.out.print("Enter your master password: ");
            String password = scanner.nextLine();
            byte[] inputHashedPassword = CryptoService.hashPassword(password, currentUser.getSalt());

            if (Arrays.equals(inputHashedPassword, currentUser.getHashedPassword())) {
                sessionKey = CryptoService.deriveKeyFromPassword(password, currentUser.getSalt());
                System.out.println("✅ Login successful!");
                return;
            } else {
                attempts++;
                System.err.println("Incorrect password. Attempts remaining: " + (3 - attempts));
            }
        }
        System.err.println("🚨 Too many failed login attempts. Exiting.");
        System.exit(1); // Or handle more gracefully
    }

    private void changePassword() throws Exception {
        System.out.println("\n--- Change Master Password ---");
        System.out.print("Enter your current master password: ");
        String currentPassword = scanner.nextLine();

        byte[] currentInputHashed = CryptoService.hashPassword(currentPassword, currentUser.getSalt());
        if (!Arrays.equals(currentInputHashed, currentUser.getHashedPassword())) {
            System.err.println("Incorrect current password. Password change failed.");
            return;
        }

        System.out.print("Enter your new master password: ");
        String newPassword = scanner.nextLine();
        System.out.print("Confirm new master password: ");
        String confirmNewPassword = scanner.nextLine();

        if (newPassword.isEmpty()){
            System.err.println("New password cannot be empty.");
            return;
        }
        if (!newPassword.equals(confirmNewPassword)) {
            System.err.println("New passwords do not match. Password change failed.");
            return;
        }

        byte[] newSalt = CryptoService.generateSalt(); // Generate a new salt for the new password
        byte[] newHashedPassword = CryptoService.hashPassword(newPassword, newSalt);

        currentUser = new User(newSalt, newHashedPassword); // Update current user object
        storageService.saveUser(currentUser); // Save new salt and hash
        sessionKey = CryptoService.deriveKeyFromPassword(newPassword, newSalt); // Update session key
        System.out.println("✅ Password changed successfully!");
    }


    private void mainMenu() {
        while (true) {
            System.out.println("\n--- Main Menu ---");
            System.out.println("1. Add New Diary Entry ✍️");
            System.out.println("2. List All Entries 🗓️");
            System.out.println("3. View Diary Entry 📖");
            System.out.println("4. Delete Diary Entry 🗑️");
            System.out.println("5. Change Master Password 🔑");
            System.out.println("0. Exit 🚪");
            System.out.print("Choose an option: ");
            String choice = scanner.nextLine();

            try {
                switch (choice) {
                    case "1":
                        addEntry();
                        break;
                    case "2":
                        listEntries();
                        break;
                    case "3":
                        viewEntry();
                        break;
                    case "4":
                        deleteEntry();
                        break;
                    case "5":
                        changePassword();
                        break;
                    case "0":
                        return; // Exit mainMenu, program will then terminate
                    default:
                        System.err.println("Invalid option. Please try again.");
                }
            } catch (Exception e) {
                System.err.println("🚨 An error occurred: " + e.getMessage());
                e.printStackTrace(); // Helpful for debugging
            }
        }
    }

    private void addEntry() throws Exception {
        System.out.println("\n--- Add New Entry ---");
        System.out.println("Enter your diary content (type ':wq' on a new line to save and quit):");
        StringBuilder contentBuilder = new StringBuilder();
        String line;
        while (!(line = scanner.nextLine()).equals(":wq")) {
            contentBuilder.append(line).append("\n");
        }
        String content = contentBuilder.toString().trim();
        if (content.isEmpty()) {
            System.out.println("Entry is empty, not saving.");
            return;
        }
        String entryId = storageService.saveEntry(content, sessionKey);
        System.out.println("✅ Entry saved successfully with ID: " + entryId);
    }

    private void listEntries() throws IOException {
        System.out.println("\n--- All Diary Entries ---");
        List<String> entryIds = storageService.listEntryIds();
        if (entryIds.isEmpty()) {
            System.out.println("No entries found.");
            return;
        }
        for (int i = 0; i < entryIds.size(); i++) {
            String entryId = entryIds.get(i);
            try {
                // Try to parse the ID as a date for more friendly display
                LocalDateTime ldt = LocalDateTime.parse(entryId, FileStorageService.DATE_TIME_FORMATTER);
                System.out.println((i + 1) + ". " + ldt.format(DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' HH:mm:ss")));
            } catch (DateTimeParseException e) {
                System.out.println((i + 1) + ". " + entryId); // Fallback to raw ID
            }
        }
    }

    private void viewEntry() throws Exception {
        System.out.println("\n--- View Diary Entry ---");
        List<String> entryIds = storageService.listEntryIds();
        if (entryIds.isEmpty()) {
            System.out.println("No entries to view.");
            return;
        }
        listEntries(); // Show them the list
        System.out.print("Enter the number of the entry to view (or 0 to cancel): ");
        int choiceNum;
        try {
            choiceNum = Integer.parseInt(scanner.nextLine());
        } catch (NumberFormatException e) {
            System.err.println("Invalid input. Please enter a number.");
            return;
        }

        if (choiceNum == 0) return;
        if (choiceNum < 1 || choiceNum > entryIds.size()) {
            System.err.println("Invalid entry number.");
            return;
        }

        String selectedId = entryIds.get(choiceNum - 1);
        DiaryEntry entry = storageService.loadEntry(selectedId);
        if (entry != null) {
            String decryptedContent = CryptoService.decrypt(entry.getEncryptedContent(), sessionKey, entry.getIv());
            System.out.println("\n--- Entry: " + selectedId + " ---");
            System.out.println(decryptedContent);
            System.out.println("--------------------------");
        } else {
            System.err.println("Could not load entry: " + selectedId);
        }
    }
     private void deleteEntry() throws Exception {
        System.out.println("\n--- Delete Diary Entry ---");
        List<String> entryIds = storageService.listEntryIds();
        if (entryIds.isEmpty()) {
            System.out.println("No entries to delete.");
            return;
        }
        listEntries(); // Show the list
        System.out.print("Enter the number of the entry to delete (or 0 to cancel): ");
        int choiceNum;
        try {
            choiceNum = Integer.parseInt(scanner.nextLine());
        } catch (NumberFormatException e) {
            System.err.println("Invalid input. Please enter a number.");
            return;
        }

        if (choiceNum == 0) return;
        if (choiceNum < 1 || choiceNum > entryIds.size()) {
            System.err.println("Invalid entry number.");
            return;
        }

        String selectedId = entryIds.get(choiceNum - 1);
        System.out.print("Are you sure you want to delete entry '" + selectedId + "'? (yes/no): ");
        String confirmation = scanner.nextLine().trim().toLowerCase();

        if (confirmation.equals("yes")) {
            if (storageService.deleteEntry(selectedId)) {
                System.out.println("✅ Entry '" + selectedId + "' deleted successfully.");
            } else {
                System.err.println("❌ Failed to delete entry '" + selectedId + "'. It might not exist anymore.");
            }
        } else {
            System.out.println("Deletion cancelled.");
        }
    }
}
