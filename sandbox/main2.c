#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main() {
    write(1, "ht\n", 3);
  return(1);
}