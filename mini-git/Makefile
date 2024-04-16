GEN_TABLES=/usr/bin/python2 gen_tables.py
LINUX_SRC=/usr/include

all: ministrace

ministrace.o: syscalls.h syscallents.h

syscallents.h: $(GEN_TABLES)
	$(GEN_TABLES) $(LINUX_SRC)
