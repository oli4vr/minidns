CC=gcc
CFLAGS=-Wall -O2
TARGET=minidns
SRC=minidns.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
