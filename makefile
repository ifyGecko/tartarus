default: tartarus.c test.c
	gcc -g -shared -fPIC tartarus.c -o tartarus.so --entry=entry
	gcc -shared -fPIC test.c -o test.so
	cp /bin/ls ./tmp

test:
	make
	LD_PRELOAD=./tartarus.so ls
	./tartarus.so ./tmp
	sudo cp ./tartarus.so /lib/x86_64-linux-gnu/
	./tmp
	sudo rm /lib/x86_64-linux-gnu/tartarus.so

clean:
	rm -f *.so *~ ./tmp
