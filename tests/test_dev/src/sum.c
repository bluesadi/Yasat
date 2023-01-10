#include <stdlib.h>

int foo(){

}

int sum(int a, int b){
    return a + b;
}

int sink(int a){
    return a;
}

int a = 23;

int main(){
    sink(a);
    a = 16;
    int b = sum(123, 456);
    sink(a + b);
}