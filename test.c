#include "global.h"

int main(int argc, char *argv[]) {
  int i = 0;
  if (!i) {
    printf("!i = 0 is true\n");
  }
  i = 1;
  if (!i) {
    printf("!i = 1 is true\n");
  }
  i = 2;
  if (!i) {
    printf("!i = 2 is true\n");
  }
  i = -1;
  if (!i) {
    printf("!i = -1 is true\n");
  }
}