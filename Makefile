CC     = gcc
CFLAGS = -Wall -Wextra -g
TARGET = City_Manager
 
all: $(TARGET)
 
$(TARGET): city_manager.c
	$(CC) $(CFLAGS) -o $(TARGET) City_Manager.c
 
clean:
	rm -f $(TARGET)
 
.PHONY: all clean
