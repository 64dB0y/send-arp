CC = g++
CFLAGS = -c -Wall
LDFLAGS = -lpcap
SOURCES = send-arp.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = send-arp

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
