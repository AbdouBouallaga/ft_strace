#include <unistd.h>
#include <fcntl.h> // Include the fcntl.h header for open function
// #include <signal.h> // Include the signal.h header for signal function
#include <stdio.h>

// void sigstop_handler(int signum) {
//   write(STDOUT_FILENO, "SIGSTOP\n", 8);
//   _exit(0);
// }

int main() {
  // int num = 2;
  // signal(SIGSTOP, sigstop_handler); // Register SIGSTOP handler
  // write(STDOUT_FILENO, "12345\n", 6);
  // int fd = open(__FILE__, O_RDONLY);
  // write(fd, "12345\n", 6);
  // close(fd);
  // read(fd, NULL, 64);
  // close(/* bogusfd = */ 1000);
  // while(num < 20){
    // printf("num = %d\n", num);
    // num = num + 2;
    // sleep(1);
    // printf("num = %d\n", num);
    // sleep(5);
    write(1, "hellohellohellohellohellohellohellohellohellohellohellohellohellohellolllllll\n", 78);
  // }
  return(1);
}