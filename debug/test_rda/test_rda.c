#include <stdlib.h>
#include <stdio.h>

char* test(){
    char* buf = (char*)malloc(16);
    memset(buf, 0, 16);
    memcpy(buf, "test", 123456);
    return buf;
}

int test2(int a, int b){
    return a + b + 123;
}

int main(){
    int seed = test2(1, 2);
    if(rand()){
        seed = 456 + rand();
    }
    seed += 20;
    srand(seed);
    printf("test");
    printf(test());
}