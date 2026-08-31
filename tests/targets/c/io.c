#include <stdio.h>

int main(void)
{
  unsigned char bytes[4];
  if (fread(bytes, 1, sizeof bytes, stdin) != sizeof bytes)
    return 1;
  fwrite(bytes, 1, sizeof bytes, stdout);
  fputc('\n', stderr);
  if (fread(bytes, 1, 1, stdin) != 0)
    return 2;
  fputs("EOF\n", stderr);
  return 0;
}
