import java.lang.reflect.Method;
import java.util.Scanner;
import java.lang.reflect.InvocationTargetException;

public class ReflectionExample {

    public static void main(String[] args) {

        // Check if a method name has been provided as an argument
        if (args.length < 1) {
            System.out.println("Please provide the name of the method to execute as a command-line argument.");
            System.out.println("Usage: java ReflectionExample <methodName>");
            return; // Exit if no method name is provided
        }

        String methodName = args[0]; // Use the first command-line argument as the method name
        
        //Scanner scanner = new Scanner(System.in);
        //System.out.println("Enter the name of the method to execute ('dynamicMethod' or 'anotherMethod'):");
        //String methodName = scanner.nextLine(); // Read method name from user input
        
        try {
            MyClass obj = new MyClass();

            // Attempt to get the method by the name entered by the user
            Method method = MyClass.class.getMethod(methodName, new Class<?>[0]); // Assuming no parameters for simplicity

            // Invoke the method dynamically on the obj instance
            method.invoke(obj); // Invoke method with no arguments
        } catch (NoSuchMethodException e) {
            System.out.println("Method not found: " + methodName);
            // Wrap and rethrow the exception
            throw new RuntimeException(e);
        } catch (IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
            // Optionally wrap and rethrow these exceptions as well if you want to handle them in the wrapper
            throw new RuntimeException(e);
        }
    }

    public static class MyClass {
        public void dynamicMethod() {
            System.out.println("Dynamic method executed.");
        }

        public void anotherMethod() {
            System.out.println("Another method executed.");
        }
    }
}
