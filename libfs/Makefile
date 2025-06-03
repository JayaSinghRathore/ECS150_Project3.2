# Compiler and flags
CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -I.

# Source and object files
SRCS    := fs.c disk.c
OBJS    := $(SRCS:.c=.o)

# Target library
LIB     := libfs.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB)
