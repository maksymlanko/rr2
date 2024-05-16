import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Checksum {

    public static void main(String[] args) {
        String filePath = "hash.txt";
        try {
            String md5Checksum = getMD5Checksum(filePath);
            System.out.println("MD5 checksum of " + filePath + " is: " + md5Checksum);
        } catch (Exception e) {
            System.err.println("Error computing MD5 checksum: " + e.getMessage());
        }
    }

    public static String getMD5Checksum(String filePath) throws NoSuchAlgorithmException, IOException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (FileInputStream fis = new FileInputStream(filePath)) {
            byte[] dataBytes = new byte[1024];
            int bytesRead;

            while ((bytesRead = fis.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, bytesRead);
            }
        }

        byte[] mdBytes = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte mdByte : mdBytes) {
            sb.append(String.format("%02x", mdByte));
        }

        return sb.toString();
    }
}

