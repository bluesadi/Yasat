import unittest
import os
import pathlib
import tarfile
import shutil
from os.path import join, isdir, exists

import tests_

COMPILERS = {
    'arm': 'arm-linux-gnueabihf-gcc',
    'mips': 'mipsel-linux-gnu-gcc'
}

COMMON_OPTIONS = '-lcrypt -lcrypto -lssl ' \
    '-Itests/common/include ' \
    '-Wno-deprecated-declarations'

def clear_dirs(*dirs):
    for dir in dirs:
        if exists(dir):
            shutil.rmtree(dir)
        pathlib.Path.mkdir(pathlib.Path(dir), exist_ok=True)

def create_dirs(*dirs):
    for dir in dirs:
        pathlib.Path.mkdir(pathlib.Path(dir), exist_ok=True)

def compile_all():
    # If 'tests/common/include/openssl' dir does not exist
    # Extract OpenSSL header files from 'tests/common/include/openssl.tar.gz'
    common_dir = join('tests', 'common')
    lib_dir = join(common_dir, 'lib')
    include_dir = join(common_dir, 'include')
    openssl_include_dir = join(include_dir, 'openssl')
    if not exists(openssl_include_dir):
        tf = tarfile.open(openssl_include_dir + '.tar.gz')
        tf.extractall(include_dir)

    # Iterate all directories starting with 'test_' in tests/, e.g., test_dev
    for filename in filter(lambda filename : filename.startswith('test_'), os.listdir('tests')):
        test_case_dir = join('tests', filename)
        if isdir(test_case_dir):
            dirs = tuple(map(lambda sub_dir : join(test_case_dir, sub_dir), 
                       ('bin', 'input', 'log', 'report', 'tmp')))
            # Clear some directories for later re-compilation
            bin_dir, input_dir, log_dir, report_dir, tmp_dir = dirs
            clear_dirs(*dirs)
            # Compile C files in src/ directory    
            src_dir = join(test_case_dir, 'src')
            for arch, compiler in COMPILERS.items():
                lib_option = f'-L{join(lib_dir, arch)}'
                output_dir = join(bin_dir, arch)
                clear_dirs(output_dir)
                for src_file in filter(lambda filename : filename.endswith('.c'), os.listdir(src_dir)):
                    output_path = join(output_dir, f'{os.path.splitext(src_file)[0]}')
                    src_path = join(src_dir, src_file)
                    compiler_command = f'{compiler} {src_path} -o {output_path} {lib_option} {COMMON_OPTIONS}'
                    os.system(compiler_command)
                    squashfs_path = join(input_dir, f'{os.path.splitext(src_file)[0]}_{arch}.bin')
                    os.system(f'mksquashfs {output_dir} {squashfs_path} -quiet')
                    
def build_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromModule(tests_))
    return suite

if __name__ == '__main__':
    compile_all()
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(build_suite())