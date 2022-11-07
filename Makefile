CXX = g++
OBJS += ./src/Main.cpp
CFLAGS += -lgmp
CFLAGS += -L/lib
CFLAGS += -I/usr/include
DIRS = bin
TARGET = ./${DIRS}/soci


all:${DIRS} ${TARGET}


${DIRS}:
	mkdir -p ${DIRS}
${TARGET}:
	${CXX} ${OBJS} -o ${TARGET} ${CFLAGS}

clean:
	-rm -fr ${DIRS}

.PHONY: all,clean