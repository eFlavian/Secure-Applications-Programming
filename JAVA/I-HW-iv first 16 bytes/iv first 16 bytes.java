
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Main {


	
	 // Helper method to convert byte array to hexadecimal string
    private static String byteArrayToHexString(byte[] array) {
        StringBuilder result = new StringBuilder();
        for (byte b : array) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
    
    public static byte[] getHash(byte[] input, String algo) {
		try {
			// Static getInstance method is called with hashing MD5
			MessageDigest md = MessageDigest.getInstance(algo);
			// digest() method is called to calculate message digest
			// of an input digest() return array of byte
			byte[] messageDigest = md.digest(input);
			return messageDigest;
		}

		// For specifying wrong message digest algorithms
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static void main(String[] args) {
		// citire fisier - prii 16 bits in Iv si restul e mesajul
		File file = new File("Msg.txt");
		byte[] msg =null;

        try (FileInputStream fis = new FileInputStream(file);
             FileChannel channel = fis.getChannel()) {

            // Allocate buffers for IV and msg
            ByteBuffer ivBuffer = ByteBuffer.allocate(16);
            ByteBuffer msgBuffer = ByteBuffer.allocate((int) channel.size() - 16);

            // Read the first 16 bytes (IV) into ivBuffer
            channel.read(ivBuffer);
            ivBuffer.flip(); // Prepare for reading

            // Read the rest of the file into msgBuffer
            channel.read(msgBuffer);
            msgBuffer.flip(); // Prepare for reading

            // Convert bytes to arrays if needed
            byte[] IV = new byte[16];
            msg= new byte[msgBuffer.remaining()];
            ivBuffer.get(IV);
            msgBuffer.get(msg);

            // Now you have the IV and msg as byte arrays
            System.out.println("IV: " + byteArrayToHexString(IV));
            System.out.println("Msg: " + new String(msg));

        } catch (IOException e) {
            e.printStackTrace();
        }
		
        msg = getHash(msg, "MD5");
     
        // Convert message digest into hex value
		BigInteger no = new BigInteger(1, msg);
		String hashtext = no.toString(16);
		while (hashtext.length() < 32) {
			hashtext = "0" + hashtext;
		}
        System.out.println("Msg MD5: " + hashtext);
        
//        X509Certificate cert = generateCertificate();
	}

}
