CC=gcc
#CFLAGS=-Wall -O3
CFLAGS= -g 
LDFLAGS+= -L./lib 
LDFLAGS+= -lpthread
LDFLAGS+= -lm
LDFLAGS+= -lrt

CFLAGS+=-I./inc
CFLAGS+=-I./include

# exteral package
#CFLAGS+=-I./inc/xml
CFLAGS+=-I./inc/json


PREFIX=/usr
BIN_DIR = $(PREFIX)/bin

SRC_DIR = src
CFILES = $(wildcard $(SRC_DIR)/*.c)
CFILES += $(wildcard $(SRC_DIR)/json/*.c)
OFILES = $(CFILES:%.c=%.o)


TARGET=Flow-class


all : $(TARGET)

$(TARGET): $(OFILES)
	$(CC) $(OFILES) -o $(TARGET) $(CFLAGS) $(LDFLAGS)


%.o: $(SRC_DIR)/%.c
	$(CC) -c $(CFLAGS) $<


install: $(TARGET)
	@echo "installing $(TARGET) to '$(BIN_DIR)'"
	@install -d -m 755 $(BIN_DIR)
	@install -m 755 $(TARGET) $(BIN_DIR)


clean:
	@echo "cleaning up"
	@rm -f $(TARGET)
	@rm -f $(OFILES)

uninstall:
	@echo "uninstalling"
	@rm $(BIN_DIR)/$(TARGET)
