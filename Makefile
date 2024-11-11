CC=gcc
# export LD_LIBRARY_PATH=/usr/lib/jvm/java-21-openjdk/lib/server:$LD_LIBRARY_PATH
# JAVA_HOME=/usr/lib/jvm/java-21-openjdk 
#
all: hello syscalls rec_rec
#all: hello mini syscalls mini-sig rec_rec

hello: HelloWorld.java
	javac HelloWorld.java

mini: hello minitrace-jni.c 
	$(CC) minitrace-jni.c -o mini-jni -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -L${JAVA_HOME}/lib/server -ljvm

syscalls: getArgLen.py syscallent.h
	python getArgLen.py

#mini-sig: hello syscalls mini-sig.c
##	$(CC) mini-sig.c -o mini-sig -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux -L${JAVA_HOME}/lib/server -ljvm
#	$(CC) -I${JAVA_HOME}/include/ -I${JAVA_HOME}/include/linux/ mini-sig.c -o mini-sig -L${JAVA_HOME}/lib/server -ljvm -I ./ -L ./ -l wrapperexample -Wl,-rpath ./

rec_rec: hello syscalls rec_rec.c
	$(CC) -std=c11 -g -I${JAVA_HOME}/include/ -I${JAVA_HOME}/include/linux/ rec_rec.c -o rec_rec -L${JAVA_HOME}/lib/server -ljvm -I ./ -L ./ -l wrapperexample -Wl,-rpath ./

NI: hello syscalls rec_rec.c
	$(CC) -std=c11 -g -DNI_ONLY -I${JAVA_HOME}/include/ -I${JAVA_HOME}/include/linux/ rec_rec.c -o ni_only -L${JAVA_HOME}/lib/server -ljvm -I ./ -L ./ -l wrapperexample -Wl,-rpath ./

perf: hello syscalls rec_rec.c 		# nothing worked :(
	$(CC) -O1 -I${JAVA_HOME}/include/ -I${JAVA_HOME}/include/linux/ rec_rec.c -o rec_rec -L${JAVA_HOME}/lib/server -ljvm -I ./ -L ./ -l wrapperexample -Wl,-rpath ./

debug: hello syscalls rec_rec.c
	$(CC) -std=c11 -DDEBUG -I${JAVA_HOME}/include/ -I${JAVA_HOME}/include/linux/ rec_rec.c -o debug -L${JAVA_HOME}/lib/server -ljvm -I ./ -L ./ -l wrapperexample -Wl,-rpath ./
#$(CC) -std=c11 -Wall -Wextra -DDEBUG -I${JAVA_HOME}/include/ -I${JAVA_HOME}/include/linux/ rec_rec.c -o debug -L${JAVA_HOME}/lib/server -ljvm -I ./ -L ./ -l wrapperexample -Wl,-rpath ./

sanitize: hello syscalls rec_rec.c
	$(CC) -std=c11 -DDEBUG -fsanitize=address -g -I${JAVA_HOME}/include/ -I${JAVA_HOME}/include/linux/ rec_rec.c -o debug -L${JAVA_HOME}/lib/server -ljvm -I ./ -L ./ -l wrapperexample -Wl,-rpath ./

full: full.c
	$(CC) -std=c11 -I${JAVA_HOME}/include/ -I${JAVA_HOME}/include/linux/ full.c -o full -L${JAVA_HOME}/lib/server -ljvm -I ./ -L ./ -l wrapperexample -Wl,-rpath ./

clean:
	rm -rf HelloWorld.class mini mini-sig syscall_args.h rec_rec

# USE NATIVE-IMG AFTER MAKING CHANGES TO JAVA FILE LIKE MD5checksum
# native-image --shared -o libwrapperexample WrapperExample
# DRIVER EXAMPLE
# java -cp .:/usr/share/java/postgresql-jdbc/postgresql-42.5.3.jar Example.java
# for native-image, WRONG????????
# native-image --shared -cp .:/usr/share/java/postgresql-jdbc/postgresql-42.5.3.jar -o libwrapperexample WrapperExample
# native-image --no-fallback Example
#
#gcc -o mini-jni minitrace-jni.c -I/usr/lib/jvm/java-21-openjdk/include -I/usr/lib/jvm/java-21-openjdk/include/linux -L/usr/lib/jvm/java-21-openjdk/lib/server -ljvm
#gcc -I ./ -L ./ -l wrapperexample -Wl,-rpath ./ -o WrapperExample
# gcc jni-example.c -o jni-ex -I/usr/lib/jvm/java-21-openjdk/include -I/usr/lib/jvm/java-21-openjdk/include/linux -L/usr/lib/jvm/java-21-openjdk/lib/server -ljvm
# gcc -I ./ -L ./ -l wrapperexample -Wl,-rpath ./ -o entry entry.c
