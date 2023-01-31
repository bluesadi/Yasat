#include "common.h"

int mul(int a, int b){
    return a * b;
}

int main(){
    int a = mul(0x91661b6e, 0x49ed48b);
    sink(a);
}