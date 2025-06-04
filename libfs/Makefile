# Compiler and flags
CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -I.
AR      := ar
ARFLAGS := rcs

# Source and object files
SRCS    := fs.c disk.c
OBJS    := $(SRCS:.c=.o)
DEPS    := $(SRCS:.c=.d)
LIB     := libfs.a

.PHONY: all clean

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

-include $(DEPS)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB) $(DEPS)
