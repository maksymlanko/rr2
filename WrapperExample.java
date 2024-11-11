 import org.graalvm.nativeimage.IsolateThread;
 import org.graalvm.nativeimage.c.function.CEntryPoint;
 import org.graalvm.nativeimage.c.type.CCharPointer;
 import org.graalvm.nativeimage.c.type.CCharPointerPointer;
 import org.graalvm.nativeimage.c.type.CTypeConversion;
 import java.lang.reflect.InvocationTargetException;
 import java.lang.reflect.Method;



public class WrapperExample {
    public static void main(String[] args) {
        try {
            //ReflectionExample.main(args);
            MD5Checksum.main(args);
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
    private static int testExceptions(IsolateThread thread, int argc, CCharPointerPointer argv) {
        try {
            if (argc < 1) {
                System.out.println("Please provide the name of the class.");
                return 0;
            }

            String[] javaArgs = new String[argc - 1];

            CCharPointer progPointer = argv.read(0);
            String progName = CTypeConversion.toJavaString(progPointer);
            //System.out.println("progName: " + progName);

            for (int i = 1; i < argc; i++) {
                CCharPointer argPointer = argv.read(i);
                javaArgs[i - 1] = CTypeConversion.toJavaString(argPointer);
            }
            
            switch (progName) {
                case "md6reflection":
                    md6reflection.main(javaArgs);
                    break;
                case "client":
                    client.main(javaArgs);
                    break;
                case "Example":
                    Example.main(javaArgs);
                    break;
                case "server":
                    server.main(javaArgs);
                    break;
                case "multiple":
                    multiple.main(javaArgs);
                    break;
                case "longExample":
                    longExample.main(javaArgs);
                    break;
                case "md6":
                    md6.main(javaArgs);
                    break;
                case "md6end":
                    md6end.main(javaArgs);
                    break;

                default:
                    System.err.println("Unknown class name: " + progName);
                    break;
            }

            /*
            // Dynamically call the main method of the specified class using reflection
            Class<?> clazz = Class.forName(progName);
            Method mainMethod = clazz.getMethod("main", String[].class);
            if (argc == 1) {
                String[] nullArr = new String[]{};
                mainMethod.invoke(null, (Object) nullArr);
            } else {
                mainMethod.invoke(null, (Object) javaArgs);
            }
            */
           
        } catch (RuntimeException e) {
            // Check if the cause is NoSuchMethodException
            if (e.getCause() instanceof NoSuchMethodException) {
                //System.out.println("NoSuchMethodException caught in wrapper: " + e.getCause().getMessage());
            }
            //e.printStackTrace();
            return -69;
        }
        return 0;
    }
}