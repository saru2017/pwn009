#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void saru()
{
  char buf[128];

//  write(2, "blue", 4);
  gets(buf);
//  write(2, "red", 3);
//  printf("%d\n", strlen(buf));
  write(1, "thank you", 9);
}

int main(){
  write(1, "hello\r\n", strlen("hello\r\n"));
  saru();

  return 0;
}

