all: myELF

myELF: myELF.o
	gcc -g -m32 -Wall -o myELF myELF.o

myELF.o: myELF.c
	gcc -g -m32 -Wall -c -o myELF.o myELF.c



clean:
	rm -f myELF.o myELF
