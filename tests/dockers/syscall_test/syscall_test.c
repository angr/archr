#define SYS_exit 60
#define SYS_write 1

int syscall(long nr, long arg1, long arg2, long arg3)
{
    long ret = 0;
    asm volatile ("syscall\n\t" : "=a"(ret) : "a"(nr), "D"(arg1),"S"(arg2),[a3]"d"(arg3));
    return ret;
}
int _start()
{
    char* message = "Hello, world!\n";
	syscall(SYS_write, 1, (long)message, 14);
	syscall(SYS_exit, 42, 0, 0);
}
