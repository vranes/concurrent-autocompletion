all: autocompletion.c
	gcc autocompletion.c -o autocompletion -pthread 


clean:
	rm autocompletion
