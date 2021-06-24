#include <stdio.h>

int main() {
    int secret = 0xdeadbeef;
    char name[100] = {0};
    read(0, name, 0x100);
    if (secret == 0xcafebabe) {
        puts("Wow! Here's a secret.");
        puts("ltdh21{Not_a_real_flag}");
    } else {
        puts("I guess you're not cool enough to see my secret");
    }
}
