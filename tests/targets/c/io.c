#include <stdio.h>

int main(void)
{
  unsigned char bytes[4];
  if (fread(bytes, 1, sizeof bytes, stdin) != sizeof bytes)
    return 1;
  fwrite(bytes, 1, sizeof bytes, stdout);
  fputc('\n', stderr);
  return 0;
}
