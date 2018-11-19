#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
	char *x;
	void *stack_left = &x;
	void *stack_right = &x;

	// get the end of the stack
	if ((unsigned long)argv > (unsigned long)stack_right) stack_right = argv;
	if ((unsigned long)envp > (unsigned long)stack_right) stack_right = envp;
	for (char **v = argv; *v != 0; v++)
	{
		if ((unsigned long)*v > (unsigned long)stack_right) stack_right = *v;
	}
	for (char **v = envp; *v != 0; v++)
	{
		if ((unsigned long)*v > (unsigned long)stack_right) stack_right = *v;
	}

	stack_right = (void *)((((unsigned long)stack_right) & ~0xfff) + 0x1000);

	setbuf(stdout, NULL);
	printf("STACK_LEFT:%p\n", stack_left);
	printf("STACK_RGHT:%p\n", stack_right);
	printf("STACK_CONTENTS:\n");
	write(1, stack_left, (unsigned long)stack_right - (unsigned long)stack_left);
	//write(1, &x, 0x1000);
}
