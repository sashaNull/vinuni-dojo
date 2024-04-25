// gcc softsec_level1.c -o softsec_level1 -Wno-implicit-function-declaration
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

void win() {
  char buffer[256];
  int flag_fd = open("/flag", O_RDONLY);

  printf("Congratulations! You win! Here is your flag:\n");

  if (flag_fd >= 0) {
    int bytes_read = read(flag_fd, buffer, sizeof(buffer));
    if (bytes_read > 0) {
      write(1, buffer, bytes_read);
      printf("\n");
      close(flag_fd);
    } else {
      printf("ERROR: Failed to read the flag!\n");
    }
  } else {
    printf("ERROR: Failed to read the flag!\n");

    int euid = geteuid();
    if (euid) {
      printf("Your effective user id is not 0!\n");
      printf("You must directly run the suid binary in order to have the "
             "correct permissions!\n");
    }
  }
}

int main(int argc, char *argv[]) {
  char class[10];
  char pennkey[8];

  strcpy(class, "EAS5120");

  printf("Enter your Pennkey: \n");

  gets(pennkey);

  if (strlen(pennkey) > 8) {
    printf("Invalid: Pennkey length must be <= 8!\n");
    exit(0);
  }

  if (strcmp(class, "EAS5120") == 0) {
    printf("Hey %s! You are enrolled in %s.\n", pennkey, class);
    sleep(1);
    printf("Hmm, the class is canceled today. See you later!\n");
  } else if (strcmp(class, "CIS5510") == 0) {
    printf("Hey %s! You are enrolled in %s.\n", pennkey, class);
    sleep(1);
    printf("%s is Sebastian's class!\n", class);
    sleep(1);
    printf("Sebastian is handing out flags to everyone in his class, %s!\n",
           pennkey);
    sleep(1);
    win();
  } else {
    printf("Who are you!? Get out of my class!\n");
  }
  exit(0);
}