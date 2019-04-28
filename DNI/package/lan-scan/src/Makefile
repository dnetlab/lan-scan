
TARGET  := lan-scan

SOURCES := main.c utils.c 
OBJS    := $(SOURCES:.c=.o)

LDFLAGS += -ladapter
IFLAGS += -I. 
CFLAGS += -Os -Wall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(IFLAGS) $<

clean:
	rm -rf $(TARGET) $(OBJS)

.PHONY: clean
