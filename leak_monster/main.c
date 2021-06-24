#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char text[1024];
    char flag[] = "AAAA";
    printf("Whats your Name Mr plumber: ");
    fgets(text, 1024 , stdin);
    printf("Hello  there ");
    printf(text);
    printf("\n");
    return(0);
}
