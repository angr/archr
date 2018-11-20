#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp, void *auxp)
{
	int x;
	setbuf(stdout, NULL);
	printf("MAIN:%p\n", main);
	printf("STACK:%p\n", &x);
	printf("ARGV:%p\n", argv);
	printf("ENVP:%p\n", envp);
	printf("AUXP:%p\n", auxp);
	printf("STDOUT:%p\n", stdout);
	printf("SMALL_MALLOC:%p\n", malloc(8));
	printf("BIG_MALLOC:%p\n", malloc(0x313370));
	printf("MMAP:%p\n", mmap(0, 0x1000, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
	//write(1, &x, 0x1000);
}
