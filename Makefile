#
CXX = g++
SRC = $(wildcard ./src/*.cpp)
OBJS = $(patsubst ./src/%.cpp, ./obj/%.o, $(SRC))
BIN = bin
CFLAGS += -lgmp
CFLAGS += -L/lib
CFLAGS += -I/usr/include
CFLAGS += -Wall
DIRS = $(BIN) obj
TARGET = ./$(BIN)/soci



all:$(DIRS) $(TARGET)


$(DIRS):
	mkdir -p $(DIRS)

$(TARGET):$(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(CFLAGS)

$(OBJS):$(SRC)
	g++ -c $< -o $@

clean:
	-rm -fr $(DIRS)

.PHONY: all,clean