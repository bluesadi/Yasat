#include "common.h"

int div(int a, int b){
    return a / b;
}

int main(){
    int a = div(0xe636039d, 0xd5c489a1);
    sink(a);
}