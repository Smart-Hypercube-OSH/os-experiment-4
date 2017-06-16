all: dirty.c
	gcc dirty.c -lpthread -O3 -o get_root

attack:
	./get_root
	touch success
	chown root success
	chgrp root success

clean:
	rm success get_root
