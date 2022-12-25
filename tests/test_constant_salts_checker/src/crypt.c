#include <unistd.h>
#include "common.h"

void test_crypt(){
    crypt(rand_bytes(8), "XX");
}

int main(){
    test_crypt();
}