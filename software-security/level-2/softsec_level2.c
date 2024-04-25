// gcc ./softsec_level2.c -o softsec_level2 -fno-PIE -no-pie -fno-stack-protector
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char buffer[256];
int flag_fd;
int euid;
ssize_t bytes_read;

void win(int pennkey) {
  if (pennkey == 0x31337) {
    printf("Congratulations! You win! Here is your flag:\n");
    flag_fd = open("/flag", O_RDONLY);

    if (flag_fd >= 0) {
      bytes_read = read(flag_fd, buffer, sizeof(buffer));
      if (bytes_read > 0) {
        write(1, buffer, bytes_read);
        printf("\n");
        close(flag_fd);
      } else {
        printf("ERROR: Failed to read the flag!\n");
      }
    } else {
      printf("ERROR: Failed to read the flag!\n");

      euid = geteuid();
      if (euid) {
        printf("Your effective user id is not 0!\n");
        printf("You must directly run the suid binary in order to have the "
               "correct permissions!\n");
      }
    }

  } else {
    printf("Incorrect password!\n");
  }
}

void expected_control_flow(void) {
  puts("This is the expected control flow.");
  exit(0);
}

void process_inputs() {
  printf("Enter your payload:\n");
  char input[9];
  read(0, input, 0x20);
}

int main() {
  process_inputs();
  expected_control_flow();
  return 0;
}