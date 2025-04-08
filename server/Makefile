compiler = gcc

source = main.c
target = main

flags = -Wextra -Wall -O2
cflags = -lpthread

all: $(target)

$(target): $(source)
        $(compiler) -o $(target) $(source) $(flags) $(cflags)

clean: $(target)
        rm $(target)
