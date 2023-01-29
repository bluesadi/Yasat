#include "common.h"

int add(int a, int b){
    return a + b;
}

int main(){
    int a = add(0x9b5bb44, 0x55ae8a);
    sink(a);
}