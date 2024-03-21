public class WrapperExample {
    public static void main(String[] args) {
        try {
            ReflectionExample.main(args);
        } catch (RuntimeException e) {
            // Check if the cause is NoSuchMethodException
            if (e.getCause() instanceof NoSuchMethodException) {
                System.out.println("NoSuchMethodException caught in wrapper: " + e.getCause().getMessage());
            } else {
                System.out.println("Other exception caught in wrapper: " + e.getMessage());
            }
            e.printStackTrace();
        }
    }
}
