CC = gcc
TARGET = dupfinder

CFLAGS = -Wall -Wextra -O2
DEBUG_FLAGS = -g -O0

LIBS = -lncursesw -lcrypto

SRC = dupfinder.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LIBS)

debug: CFLAGS = $(DEBUG_FLAGS) -Wall -Wextra
debug: clean $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

run: $(TARGET)
	./$(TARGET) ./test -r

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/