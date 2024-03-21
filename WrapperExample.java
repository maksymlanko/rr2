 import org.graalvm.nativeimage.IsolateThread;
 import org.graalvm.nativeimage.c.function.CEntryPoint;
 import org.graalvm.nativeimage.c.type.CCharPointer;
 import org.graalvm.nativeimage.c.type.CTypeConversion;
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;



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

    @CEntryPoint(name = "run_c")
    private static int testExceptions(IsolateThread thread, CCharPointer cFilter) {
        System.out.println("Entrei");
        try {
            String arg = CTypeConversion.toJavaString(cFilter);
            String[] mainArgs = new String[]{arg}; // Example arguments to main
            ReflectionExample.main(mainArgs);
            return 0;
        } catch (RuntimeException e) {
            // Check if the cause is NoSuchMethodException
            if (e.getCause() instanceof NoSuchMethodException) {
                System.out.println("NoSuchMethodException caught in wrapper: " + e.getCause().getMessage());
            } else {
                System.out.println("Other exception caught in wrapper: " + e.getMessage());
            }
            e.printStackTrace();
            return -1;
        }
    }
}
