import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class md6 {

    public static void main(String[] args) {

        System.out.println("Entrei");

        String filePath = "hash.txt";
        byte[] fileBytes = null;
        try {
            fileBytes = readFile(filePath);
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
            e.printStackTrace();
            return; // Exit if there's an error reading the file
        }

	    System.out.println(new String(fileBytes));

        try {
            String md6Checksum = getMD6Checksum(fileBytes);
            System.out.println("MD6 checksum of " + filePath + " is: " + md6Checksum);
        } catch (Exception e) {
            System.err.println("Error computing MD6 checksum: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static byte[] readFile(String filePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] dataBytes = new byte[fis.available()];
            fis.read(dataBytes);
            return dataBytes;
        }
    }

    public static String getMD6Checksum(byte[] fileBytes) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(fileBytes);
        byte[] mdBytes = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte mdByte : mdBytes) {
            sb.append(String.format("%02x", mdByte));
        }
        return sb.toString();
    }

}

