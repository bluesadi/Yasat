#include <stdlib.h>

int foo(){

}

int sum(int a, int b){
    return a + b;
}

int sink(int a){
    return a;
}

int main(){
    sink(123);
}