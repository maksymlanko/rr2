import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class md6reflection {

    public static void main(String[] args) {
       
	    if (args.length < 1) {
            System.out.println("Please provide the name of the method to execute as a command-line argument.");
            System.out.println("Usage: java md6reflection <methodName>");
            return;
        }

        System.out.println("Entrei");

        String methodName = args[0];

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
            md6reflection obj = new md6reflection();
            Method method = md6reflection.class.getMethod(methodName, new Class<?>[0]);
            method.invoke(obj);
        } catch (NoSuchMethodException e) {
            System.out.println("Method not found: " + methodName);
            throw new RuntimeException(e);
        } catch (IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        try {
            Method method = md6reflection.class.getMethod("getMD6Checksum", byte[].class);
            String md6Checksum = (String) method.invoke(null, (Object) fileBytes);
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

    public void dynamicMethod() {
        System.out.println("Dynamic method executed.");
    }

    public void anotherMethod() {
        System.out.println("Another method executed.");
    }
}

