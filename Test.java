package test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Test {
    //    PART I (10 points)
//    A DB admin asks for your help to update the hash value of a user in his/her database.
//    He sent you that user password in an encrypted file (with a .user extension). Search for that file as you know its SHA256 hash value in Base64 format.
//    Print the designated file name at the console.
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, SignatureException, InvalidKeyException {
        // Define the target SHA256 hash value in Base64 format
        String targetHashBase64 = "BAYkwa36wNGPTOy/lQXK3Tbm3V8Vf0iUXiDCTstfavQ=";

        // Path to the .zip file containing the .user files
        String zipFilePath = "C:\\Users\\Stefania\\IdeaProjects\\JavaHW2\\src\\test\\userFiles.zip";

        try (FileInputStream fis = new FileInputStream(zipFilePath);
             ZipInputStream zipStream = new ZipInputStream(fis)) {

            ZipEntry entry;
            while ((entry = zipStream.getNextEntry()) != null) {
                if (entry.getName().endsWith(".user")) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    MessageDigest md = MessageDigest.getInstance("SHA-256");

                    while ((bytesRead = zipStream.read(buffer)) != -1) {
                        md.update(buffer, 0, bytesRead);
                    }

                    byte[] hashBytes = md.digest();
                    String fileHashBase64 = Base64.getEncoder().encodeToString(hashBytes);

                    // Check if the hash matches the target hash
                    if (fileHashBase64.equals(targetHashBase64)) {
                        System.out.println("Match found: " + entry.getName());
                        break;
                    }
                }
            }

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
//    PART II (5 points)
//    Once you found the file, decrypt it (AES in CBC mode with a known IV - check the user's file. There is no need for Padding as the file has the required size) using the password sent by your friend (check the users.pdf file).
//    The decrypted content represents the user password as a string with 16 characters.
//    Print the user password at the console.
        String filename = "C:\\Users\\Stefania\\IdeaProjects\\JavaHW2\\src\\test\\User68.user"; // Replace with the actual file path
        String password = "your_friend_provided_password"; // Replace with actual password from users.pdf
        String decryptedOutputFile = "decrypted_user_password.txt";

        try {
            decrypt(filename, decryptedOutputFile, password);
            printDecryptedPassword(decryptedOutputFile);
        } catch (Exception e) {
            e.printStackTrace();
        }
//    PART III (5 points)
//    Add to the user password the "ism2021" salt at the end and hash it with the PBKDF (Password-Based Key Derivation Function) based on HmacSHA1 algorithm with 150 iterations. The output must have 20 bytes.
//    Store the result in a binary file (you can choose the filename name). To get the points, the value must be validated by your friend.
        String salt = "ism2021";
        String decryptedPassword = readDecryptedPassword(decryptedOutputFile);
        byte[] hashedPassword = getPBKDF(decryptedPassword, "PBKDF2WithHmacSHA1", salt, 150);

        // Store the result in a binary file
        String binaryOutputFile = "hashed_user_password.bin";
        writeBinaryFile(binaryOutputFile, hashedPassword);
//    PART IV (5 points)
//    To assure your friend that no one is tampering with that value, digitally sign the previous binary file with your private key. Store the signature in another binary file.
//    Using keytool generate a RSA pair. Export the public key in a X509 .cer file. Use the private key to sign the previous file.
//    Send your colleague the binary files with the signature and your public certificate.
//    To get points the digital signature must be validated for the previous file with your public key.


        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can choose the key size
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
// Convert the public key to X509 format
        byte[] publicKeyBytes = publicKey.getEncoded();
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);

// Generate a certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (FileInputStream certFile = new FileInputStream("public_certificate.cer")) {
            cert = (X509Certificate) cf.generateCertificate(certFile);
        } catch (CertificateException e) {
            e.printStackTrace();
            return; // Exit if certificate loading fails
        }
// Save the certificate to a .cer file
        try (FileOutputStream fos = new FileOutputStream("public_certificate.cer")) {
            fos.write(cert.getEncoded());
            byte[] dataToSign = readBinaryFile("hashed_user_password.bin"); // Read the binary data
        }

        byte[] digitalSignature = signFile("hashed_user_password.bin", privateKey);

        // Save the digital signature to a binary file
        writeBinaryFile("digital_signature.bin", digitalSignature);

        // Verify the signature using the public key from the certificate
        boolean isValid = hasValidSignature("hashed_user_password.bin", cert.getPublicKey(), digitalSignature);
        System.out.println("Signature is valid: " + isValid);
    }
    public static void writeBinaryFile(String filename, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename);
             BufferedOutputStream bos = new BufferedOutputStream(fos);
             DataOutputStream dos = new DataOutputStream(bos)) {

            // Write binary data using DataOutputStream
            dos.writeInt(data.length);
            dos.write(data);
        }
    }

    public static String readDecryptedPassword(String decryptedOutputFile) throws IOException {
        try (FileReader fileReader = new FileReader(decryptedOutputFile);
             BufferedReader bufferedReader = new BufferedReader(fileReader)) {

            String line;
            StringBuilder decryptedPassword = new StringBuilder();

            while ((line = bufferedReader.readLine()) != null) {
                System.out.println("File line: " + line);
                decryptedPassword.append(line);
            }

            return decryptedPassword.toString();
        }
    }

    public static byte[] getPBKDF(String userPassword, String algorithm, String salt, int noIterations) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeySpecException {
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance(algorithm);
        PBEKeySpec pbkdfSpecifications = new PBEKeySpec(userPassword.toCharArray(), salt.getBytes(), noIterations, 256);
        SecretKey secretKey = pbkdf.generateSecret(pbkdfSpecifications);
        return secretKey.getEncoded();
    }

    public static void decrypt(String filename, String outputFile, String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        File file = new File(filename);
        byte[] msg = null;
        byte[] IV = new byte[16];

        try (FileInputStream fis = new FileInputStream(file);
             FileChannel channel = fis.getChannel()) {

            ByteBuffer ivBuffer = ByteBuffer.allocate(16);
            ByteBuffer msgBuffer = ByteBuffer.allocate((int) channel.size() - 16);

            channel.read(ivBuffer);
            ivBuffer.flip();

            channel.read(msgBuffer);
            msgBuffer.flip();

            ivBuffer.get(IV);
            msg = new byte[msgBuffer.remaining()];
            msgBuffer.get(msg);
        }

        byte[] key = getHash(password.getBytes(StandardCharsets.UTF_8), "MD5");

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] output = cipher.doFinal(msg);
            fos.write(output);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getHash(byte[] input, String algo) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algo);
        return md.digest(input);
    }

    private static void printDecryptedPassword(String decryptedOutputFile) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(decryptedOutputFile))) {
            String decryptedPassword = reader.readLine();
            System.out.println("Decrypted User Password: " + decryptedPassword);
        }
    }

    public static byte[] extractIVFromFile(String userFilePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(userFilePath);
             BufferedInputStream bis = new BufferedInputStream(fis)) {
            byte[] iv = new byte[16]; // 16 bytes for AES
            if (bis.read(iv) != iv.length) {
                throw new IOException("Could not read the IV from the file");
            }
            return iv;
        }
    }
    public static byte[] readBinaryFile(String filename) throws IOException {
        try (FileInputStream fis = new FileInputStream(filename);
             BufferedInputStream bis = new BufferedInputStream(fis)) {

            byte[] fileContent = new byte[(int) new File(filename).length()];
            int bytesRead = bis.read(fileContent);

            if (bytesRead != fileContent.length) {
                throw new IOException("Could not read the entire binary file");
            }

            return fileContent;
        }
    }
    public static byte[] signFile(String filename, PrivateKey key) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        File file = new File(filename);
        if(!file.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(file);

        byte[] fileContent = fis.readAllBytes();

        fis.close();

        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(key);

        signature.update(fileContent);
        return signature.sign();
    }
    public static boolean hasValidSignature(String filename, PublicKey key, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        File file = new File(filename);
        if(!file.exists()) {
            throw new FileNotFoundException();
        }

        FileInputStream fis = new FileInputStream(file);
        byte[] fileContent = fis.readAllBytes();
        fis.close();

        Signature signatureModule = Signature.getInstance("SHA512withRSA");
        signatureModule.initVerify(key);

        signatureModule.update(fileContent);
        return signatureModule.verify(signature);

    }
}