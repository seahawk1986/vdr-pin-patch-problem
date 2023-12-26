#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main (int argc, char *argv[]) {
   if (setuid(0) == 0) {
      return execv("/usr/lib/vdr/vdr-shutdown", argv);
   } else {
      perror("Could not set uid to 0");
      return 1;
   }
}
