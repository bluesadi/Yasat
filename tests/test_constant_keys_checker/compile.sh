module="test_constant_keys_checker"
libs="-lcrypt -lcrypto -lssl"
common_options="-I../common/include -Wno-deprecated-declarations"

for src in src/*.c
do
    bin=$(echo $(basename $src) | cut -d . -f1)
    
    arm-linux-gnueabihf-gcc $src -o bin/arm/$bin -L../common/lib/arm $libs $common_options
    mipsel-linux-gnu-gcc $src -o bin/mips/$bin -L../common/lib/mips $libs $common_options
done

rm -f input/${module}_arm.bin input/${module}_mips.bin
mksquashfs bin/arm ${module}_arm.bin -quiet
mksquashfs bin/mips ${module}_mips.bin -quiet

mv ${module}_arm.bin input/${module}_arm.bin
mv ${module}_mips.bin input/${module}_mips.bin