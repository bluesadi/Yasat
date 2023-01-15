#include <stdlib.h>

int foo(){

}

int sum(int a, int b){
    return a + b;
}

int sink(char* a){
    return a;
}

char* a = "123";

int main(){
    sink(a);
}