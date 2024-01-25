import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, UnrecoverableKeyException {

        // 1. Check for file changes.
        checkFileForChanges("SAPExamSubject1");
        checkFileForChanges("SAPExamSubject2");
        checkFileForChanges("SAPExamSubject3");

        // 2. Generate AES 128 key for encrypting with ECB my response
        byte[] secretKey = generateKey(128);

//        for(byte bvalue : secretKey) {
//            System.out.println("\n The secretKey is " + bvalue);
//        }

        encrypt("response.txt","response.sec", secretKey,"AES");

        //3. Generate your own RSA public-private pair using keytool (the certificate owner must be you and not ISM)

        //4. Encrypt the AES key with the professor public key
        PublicKey professorKey = getCertificateKey("SimplePGP_ISM.cer");
        byte[] encryptedAESKey = encryptKey(professorKey, secretKey);
        writeBinaryFile(encryptedAESKey, "aes_key.sec");

        //5. Compute a digital signature for the response file and save it in a signature.ds binary file

        //digital signatures
        //generate a digital signature (RSA) for a file with private key
        //validate the digital signature with public key

        KeyStore ks = getKeyStore("ismkeystore.ks", "passkey", "pkcs12");
        PrivateKey personalPrivateKey = getPrivateKey("hwflaviankey","passkey",ks);
        PublicKey personalPublicKey = getCertificateKey("HWEneFlavianCertificateX509.cer");

        byte[] signature = signFile("response.sec", personalPrivateKey);

        System.out.println("Digital signature value: ");
        System.out.println(getHexString(signature));

        if(hasValidSignature("response.sec", personalPublicKey, signature))
        {
            System.out.println("The response.sec file is the original one!");
        } else {
            System.out.println("File has been changed");
        }
        writeBinaryFile(signature, "signature.ds");
    }

    public static KeyStore getKeyStore(
            String keyStoreFile,
            String keyStorePass,
            String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        File file = new File(keyStoreFile);
        if(!file.exists()) {
            throw new UnsupportedOperationException("Missing key store file");
        }

        FileInputStream fis = new FileInputStream(file);

        KeyStore ks = KeyStore.getInstance(keyStoreType);
        ks.load(fis, keyStorePass.toCharArray());

        fis.close();
        return ks;
    }

    public static PrivateKey getPrivateKey(
            String alias, String keyPass, KeyStore ks ) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        if(ks == null) {
            throw new UnsupportedOperationException("Missing Key Store");
        }
        if(ks.containsAlias(alias)) {
            return (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
        } else {
            return null;
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

    public static void writeBinaryFile(byte[] input, String fileName) throws IOException {

        File dataFile = new File(fileName);
        if(!dataFile.exists()) {
            dataFile.createNewFile();
        }
        FileOutputStream fos = new FileOutputStream(dataFile);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        DataOutputStream dos = new DataOutputStream(bos);
        dos.write(input);

        dos.close();
    }

    public static byte[] encryptKey(Key key, byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    public static void encrypt(
            String filename, String cipherFilename, byte[] password, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        File inputFile = new File(filename);
        if(!inputFile.exists()) {
            throw new UnsupportedOperationException("Missing file");
        }
        File cipherFile = new File(cipherFilename);
        if(!cipherFile.exists()) {
            cipherFile.createNewFile();
        }

        FileInputStream fis = new FileInputStream(inputFile);
        FileOutputStream fos = new FileOutputStream(cipherFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(password, algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] buffer = new byte[cipher.getBlockSize()];
        int noBytes = 0;

        while(true) {
            noBytes = fis.read(buffer);
            if(noBytes == -1) {
                break;
            }
            byte[] cipherBlock = cipher.update(buffer, 0, noBytes);
            fos.write(cipherBlock);
        }
        //get the last ciphertext block
        byte[] lastBlock = cipher.doFinal();
        fos.write(lastBlock);

        fis.close();
        fos.close();
    }

    public static byte[] generateKey(int noBytes) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed("Some seed.".getBytes());
        keyGenerator.init(noBytes, secureRandom);
        return keyGenerator.generateKey().getEncoded();
    }

    static void checkFileForChanges(String filename) throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        byte[] signature = getSignatureFromFile(filename+".signature");
        System.out.println("Digital signature value: ");
        System.out.println(getHexString(signature));

        PublicKey publicKey = getCertificateKey("SimplePGP_ISM.cer");

        if(hasValidSignature(
                filename+".txt", publicKey, signature))
        {
            System.out.println("File is the original one\n");
        } else {
            System.out.println("File has been changed\n");
        }
    }
    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        result.append("0x");
        for(byte b : value) {
            result.append(String.format(" %02X", b));
        }
        return result.toString();
    }
    public static PublicKey getCertificateKey(String certificateFile) throws CertificateException, IOException {
        File file = new File(certificateFile);
        if(!file.exists()) {
            throw new UnsupportedOperationException("****Missing file****");
        }
        FileInputStream fis = new FileInputStream(file);

        CertificateFactory certFactory =
                CertificateFactory.getInstance("X.509");
        X509Certificate certificate =
                (X509Certificate) certFactory.generateCertificate(fis);
        fis.close();
        return certificate.getPublicKey();
    }

    public static byte[] getSignatureFromFile(String filename) throws IOException {
        File file = new File(filename);
        if(!file.exists()) {
            throw new FileNotFoundException();
        }
        FileInputStream fis = new FileInputStream(file);

        byte[] fileContent = fis.readAllBytes();

        fis.close();
        return fileContent;
    }

    public static boolean hasValidSignature(
            String filename, PublicKey key, byte[] signature) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

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