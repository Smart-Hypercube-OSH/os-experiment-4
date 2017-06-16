all: dirty.c
	gcc dirty.c -lpthread -o get_root

attack:
	./get_root

clean:
	rm success get_root
