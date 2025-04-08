compiler = gcc

target = main.c
final = main

flags = -lpthread
cflags = -Wextra -Wall -O2

all: $(final)

$(final): $(target)
        $(compiler) -o $(final) $(target) $(flags) $(cflags)

clean: $(final)
        rm $(final)
