#include <stdlib.h>

int foo(){

}

int sum(int a, int b){
    return a + b;
}

int sink(char* a){
    return a;
}

int a = 123;

int main(){
    int r = rand();
    for(int i = 0;i < r; i++){
        sink(i);
    }
}