#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void gen_file(void){
    system("touch test.txt");
}

void vuln_func(void){
    char str[96];
    while(1){
        gets(str);
        printf(str);
        if (!strcmp(str, "exit")){
            break;
        }
    }
}

int main(void){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln_func();
    return 0;
}
