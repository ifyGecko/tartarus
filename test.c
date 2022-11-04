#include <stdio.h>

void __attribute__((constructor)) test(){
  printf("hello, world!\n");
}
