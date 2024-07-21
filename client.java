import java.io.*;
import java.net.*;

public class client {
    public static void main(String[] args) {
        System.out.println("Entrei");
        String hostname = "localhost";
        int port = 12345;

        try (Socket socket = new Socket(hostname, port)) {
            System.out.println("Depois de criar socket");
            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));

            String message = reader.readLine();
            System.out.println("Message from server: " + message);
        } catch (UnknownHostException ex) {
            System.out.println("Server not found: " + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("I/O error: " + ex.getMessage());
        }
        System.out.println("Sai");
    }
}

