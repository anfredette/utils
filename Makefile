# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2

# Include directories
INCLUDES = -I. -lbpf

# Source files
SRCS = $(wildcard *.c)

# Executable names
EXECS = $(SRCS:.c=)

# Default target
all: $(EXECS)

# Rule to build each executable
%: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

# Clean up build files
clean:
	rm -f $(EXECS) *.o

# Phony targets
.PHONY: all clean
