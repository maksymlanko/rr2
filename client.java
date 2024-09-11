import java.io.*;
import java.net.*;
import java.lang.reflect.Method;

public class client {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Please provide the name of the method to execute as a command-line argument.");
            System.out.println("Usage: java client <methodName>");
            return;
        }

        System.out.println("Entrei");
        String methodName = args[0];

        String hostname = "localhost";
        int port = 12345;

        try {
            Socket socket = new Socket(hostname, port);
            System.out.println("Depois de criar socket");
            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));

            // Now execute the dynamic method
            client obj = new client();
            Method method = client.class.getMethod(methodName);
            method.invoke(obj);

            String message = reader.readLine();
            System.out.println("Message from server: " + message);
            
        } catch (UnknownHostException ex) {
            System.out.println("Server not found: " + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("I/O error: " + ex.getMessage());
        } catch (Exception e) {
            //System.out.println("Error executing method: " + e.getMessage());
            //e.printStackTrace();
            throw new RuntimeException(e);
        }

        System.out.println("Sai");
    }

    public void dynamicMethod() {
        System.out.println("Dynamic method executed.");
    }

    public void anotherMethod() {
        System.out.println("Another method executed.");
    }
    
    public void hello() {
        System.out.println("Hello executed.");
    }
}