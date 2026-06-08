#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    pid_t pid = getpid();
    printf("Test Target PID: %d\n", pid);

    // 1. Allocate on heap and populate with a dummy PNG magic header and plain text
    size_t heap_size = 512;
    char *heap_buf = malloc(heap_size);
    if (!heap_buf) {
        perror("malloc failed");
        return 1;
    }
    memset(heap_buf, 0, heap_size);
    
    // PNG Header: \x89PNG\r\n\x1a\n
    heap_buf[0] = 0x89;
    heap_buf[1] = 0x50; // P
    heap_buf[2] = 0x4E; // N
    heap_buf[3] = 0x47; // G
    heap_buf[4] = 0x0D; // \r
    heap_buf[5] = 0x0A; // \n
    heap_buf[6] = 0x1A; // EOF
    heap_buf[7] = 0x0A; // \n
    
    strcpy(heap_buf + 8, "HEAP_DATA: This is a secret message hidden inside a simulated PNG file in process heap memory! Recovered successfully.");
    
    // 2. Allocate on stack and populate with a custom magic header and plain text
    char stack_buf[512];
    memset(stack_buf, 0, sizeof(stack_buf));
    
    // Custom magic: "MY_MAGIC_SECRET_123"
    const char *custom_magic = "MY_MAGIC_SECRET_123";
    strcpy(stack_buf, custom_magic);
    strcpy(stack_buf + strlen(custom_magic), " | STACK_DATA: The database root password is 'SuperSecretAntigravity2026!'. Keep this safe!");

    printf("Secret strings have been initialized in memory.\n");
    printf("- Heap address: %p\n", (void*)heap_buf);
    printf("- Stack address: %p\n", (void*)stack_buf);
    printf("\nSleeping for 300 seconds to keep memory alive...\n");
    sleep(300);

    free(heap_buf);
    return 0;
}
