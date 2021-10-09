#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv) {
    int fd = open("mapped_file", O_RDWR);
    char* mmapped_region = mmap(NULL, 0x1000,
                                PROT_READ|PROT_WRITE,
                                MAP_FILE|MAP_PRIVATE,
                                fd, 0);
    munmap(mmapped_region, 0x1000);
    close(fd);
    return 0;
}