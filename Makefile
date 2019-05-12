CC=gcc
CFLAGS=-c -pthread -Wno-unused-result -g -std=gnu99
LDFLAGS=-pthread
SOURCES=main.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=proxy

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
