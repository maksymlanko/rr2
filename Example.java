import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class Example {
   static final String DB_URL = "jdbc:postgresql://127.0.0.1:5432/jdbc_experiment";
   static final String USER = "postgres";
   static final String PASS = "0000";
   static final String QUERY = "SELECT id, manufacturer, model FROM cars";

   public static void main(String[] args) {
      try {
         System.out.println("Entrei");
         System.out.println("Connection to DB in progress...");
         // Open a connection
         Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
         Statement stmt = conn.createStatement();
         ResultSet rs = stmt.executeQuery(QUERY);
         // Extract data from result set
         while (rs.next()) {
            // Retrieve by column name
            System.out.print("ID: " + rs.getInt("id"));
            System.out.print(", Manufacturer: " + rs.getString("manufacturer"));
            System.out.println(", Model: " + rs.getString("model"));
         }
         conn.close();
      } catch (SQLException e) {
         //e.printStackTrace();
         //System.out.println("Sai exception");
         throw new RuntimeException(e);
      }

      System.out.println("Sai");
   }
}