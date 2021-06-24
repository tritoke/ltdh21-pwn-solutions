#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void printFlag() { 
	puts("ltdh21{N0t_A_r3Al_flAg}");
}

typedef struct {
	uint8_t methodName[20];
	uintptr_t (*func)();
} Object;

void boringFunction() { 
	puts("I'm a real boring function, that dont do much..."); 
}

void printAndRun(Object* obj) {
	printf("Calling %s\n", obj->methodName);
	(*obj->func)();
}

int main(int argc, char **argv) {
	Object *obj = (void *)malloc(sizeof(Object));
	obj->func = (void *)boringFunction;
	strcpy(obj->methodName, "boringFunction");

	printAndRun(obj);

	free(obj);

	uint8_t *userInput = (void *)malloc(32);
	read(STDIN_FILENO, userInput, 32);

	printAndRun(obj);

	return 0;
}
