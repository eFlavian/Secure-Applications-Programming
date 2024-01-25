
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class Main {

    private static final int THREAD_POOL_SIZE = 20;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        String hashValue = "e6fe859c6a5352eff302a35f1642e1173b63199821bef384388850543f8aba68";
        String prefix = "ismsap";
        AtomicReference<String> password = new AtomicReference<>("");

        File messageTextFile = new File("ignis-10M.txt");

        if (!messageTextFile.exists()) {
            throw new FileNotFoundException("File not found: " + messageTextFile.getPath());
        }

        FileReader fileReader = new FileReader(messageTextFile);
        BufferedReader bufferedReader = new BufferedReader(fileReader);

//        File messageBinaryFileWrite = new File("passHashed.dat");
//        if (!messageBinaryFileWrite.exists()) {
//            messageBinaryFileWrite.createNewFile();
//        }

        ExecutorService executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

        long tstart = System.currentTimeMillis();

        long count = 0;

        String selectedPass;
        while ((selectedPass = bufferedReader.readLine()) != null) {
            count++;

            final String passwordToCheck = selectedPass;

            executorService.submit(() -> {
                try {
                    byte[] binaryData = passwordToCheck.getBytes();
                    byte[] passMd5 = getMessageDigest(concatArrays(prefix.getBytes(), binaryData), "MD5");
                    byte[] passSha256 = getMessageDigest(passMd5, "SHA-256");

//                  System.out.println(count + " | Result MD5: " + getHexString(passMd5));
//                  System.out.println(count + " | Result SHA256: " + getHexString(passSha256));
//                  System.out.println(count + " | Wanted: " + hashValue);

                    if (hashValue.equals(getHexString(passSha256))) {
                        synchronized (Main.class) {
                            password.set(passwordToCheck);
                            System.out.println("FOUND FOUND FOUND: \n" + passwordToCheck + '\n');
                        }
                    }
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    e.printStackTrace();
                }
            });
        }

        executorService.shutdown();

        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        long tfinal = System.currentTimeMillis();
        System.out.println("Password is: " + password.get());

        long durationMillis = tfinal - tstart;
        long durationSeconds = durationMillis / 1000;
        long durationMinutes = durationMillis / (60 * 1000);

        System.out.println("Duration of the process: " + durationMinutes + " min, " + ((durationSeconds - (durationMinutes) * 60)) + " sec.");
    }

    public static byte[] getMessageDigest(byte[] input, String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest md = MessageDigest.getInstance(algorithm, "SUN");
        return md.digest(input);
    }

    public static byte[] concatArrays(byte[] first, byte[] second) {
        byte[] result = new byte[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static String getHexString(byte[] value) {
        StringBuilder result = new StringBuilder();
        for (byte b : value) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

}
