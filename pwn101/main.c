#include <string.h>
#include <stdio.h> 

void secret() {
	puts("ltdh21{N0t_T0dAy_SuCK3r5}\n");
}

void name() {
	puts("What is your name: ");
	char str[20]; 
	gets(str);
	printf("Hello %s\n", str); 
}

int main( int argc, char** argv ) {
	printf("There is a secret at: %p\n", secret);
	name();
	return 0; 
}
