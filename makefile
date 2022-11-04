default: tartarus.c test.c
	gcc -g -shared -fPIC tartarus.c -o tartarus.so --entry=entry
	gcc -shared -fPIC test.c -o test.so
	cp /bin/ls ./tmp

test:
	make
	LD_PRELOAD=./tartarus.so ls
	./tartarus.so ./tmp
	./tmp

clean:
	rm -f *.so *~ ./tmp
