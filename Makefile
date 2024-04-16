CC=gcc
# export LD_LIBRARY_PATH=/usr/lib/jvm/java-21-openjdk/lib/server:$LD_LIBRARY_PATH
# JAVA_HOME=/usr/lib/jvm/java-21-openjdk 
#
all: hello mini mini-sig

hello: HelloWorld.java
	javac HelloWorld.java

mini: hello minitrace-jni.c 
	$(CC) minitrace-jni.c -o mini-jni -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -L${JAVA_HOME}/lib/server -ljvm

mini-sig: hello mini-sig.c
	$(CC) mini-sig.c -o mini-sig -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -L${JAVA_HOME}/lib/server -ljvm

clean:
	rm -rf HelloWorld.class mini mini-sig


#gcc -o mini-jni minitrace-jni.c -I/usr/lib/jvm/java-21-openjdk/include -I/usr/lib/jvm/java-21-openjdk/include/linux -L/usr/lib/jvm/java-21-openjdk/lib/server -ljvm
