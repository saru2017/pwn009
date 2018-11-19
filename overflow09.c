#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void saru()
{
  char buf[128];

  puts("password?: ");
  fflush(stdout);
  gets(buf);
  puts("thank you!");
  fflush(stdout);
}

int main(){
  saru();

  return 0;
}

