// gcc ./softsec_level6.c -o softsec_level6 -fno-stack-protector -z execstack -lseccomp
#include <assert.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <unistd.h>

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

void restrict_syscall() {
  scmp_filter_ctx ctx;
  puts("Restricting system calls (default: kill).\n");
  ctx = seccomp_init(SCMP_ACT_KILL);
  printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
  printf("Allowing syscall: %s (number %i).\n", "open", SCMP_SYS(open));
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
  printf("Allowing syscall: %s (number %i).\n", "exit", SCMP_SYS(exit));
  assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

  assert(seccomp_load(ctx) == 0);
}

void read_elements(FILE *f, char *buf, unsigned long count) {
  unsigned long i;
  for (i = 0; i < count; i++) {
    if (fread(&buf[i], sizeof(char), 1, f) < 1) {
      break;
    }
  }

  restrict_syscall();
}

void read_file(char *name) {
  FILE *f = fopen(name, "rb");
  if (!f) {
    fprintf(stderr, "Error: Cannot open file\n");
    return;
  }

  unsigned long record_num;
  fread(&record_num, sizeof(unsigned long), 1, f);
  if (!record_num) {
    fprintf(stderr, "Error: record_num must be > 0!\n");
    return;
  }

  unsigned int record_size;
  fread(&record_size, sizeof(unsigned int), 1, f);
  if (!record_size) {
    fprintf(stderr, "Error: record_size must be > 0!\n");
    return;
  }

  char *buf = alloca(record_num * record_size);
  if (!buf) {
    return;
  }
  printf("Reading element to buffer at %p!\n", buf);
  sleep(1);

  read_elements(f, buf, record_num);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Error: Need an input filename\n");
    return 1;
  }

  read_file(argv[1]);
  return 0;
}