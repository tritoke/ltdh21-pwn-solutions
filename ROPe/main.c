#include <string.h>
#include <stdio.h>

void name() {
	char str[20];
   	puts("What is your name: ");
	gets(str);
   	printf("Hello %s\n", str);
}

int main( int argc, char** argv ) {
    name();
    return 0;
}
