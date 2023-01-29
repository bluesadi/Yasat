#include "common.h"

int sub(int a, int b){
    return a - b;
}

int main(){
    int a = sub(0x45146a6b, 0x90e090ec);
    sink(a);
}