#include <stdlib.h>

int foo(int a, int b, int c, int d, int e, int f){
    if(rand()) return b;
    else if(rand()) return c;
    else if(rand()) return d;
    else if(rand()) return e;
    else if(rand()) return f;
    return a;
}

int sum(int a, int b){
    return a + b;
}

int sink(char* a){
    return a;
}

int main(){
    unsigned int a = -0x123;
    char b = 2;
    sink(a >> b);
}