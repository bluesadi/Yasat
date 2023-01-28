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

int a = 1;
int b = 2;
int c = 3;
int d = 4;
int e = 5;
int f = 6;

int main(){
    sink(foo(a, b, c, d, e, f));
}