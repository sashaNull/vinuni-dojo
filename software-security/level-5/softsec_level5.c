// gcc ./softsec_level5.c -o softsec_level5 -fno-stack-protector -z execstack
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <unistd.h>

#define BUFFER_SIZE 0x2000

void __attribute__((constructor))
disable_aslr(int argc, char **argv, char **envp) {
  int current_personality = personality(0xffffffff);
  assert(current_personality != -1);
  if ((current_personality & ADDR_NO_RANDOMIZE) == 0) {
    assert(personality(current_personality | ADDR_NO_RANDOMIZE) != -1);
    assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != -1);
    execve("/proc/self/exe", argv, envp);
  }
}

void move_buffer(char *arg) {
  long long *p;
  long long a;
  char buf[2051];
  printf("Src Address: %p\n", arg);
  printf("Dest Address: %p\n", &buf);
  printf("MOVING.............\n");
  sleep(1);
  memcpy(buf, arg, sizeof(buf) + 0x17);
  printf("FLUSH..............\n");
  sleep(1);
  memset(arg, '\0', BUFFER_SIZE);
  *p = a;
}

int main() {
  printf("Enter your payload: \n");
  char buf[BUFFER_SIZE];
  read(0, buf, BUFFER_SIZE);
  move_buffer(buf);
  return 0;
}
