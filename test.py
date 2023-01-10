import unittest
import os
import pathlib
import tarfile

import tests

COMPILERS = {
    'arm': 'arm-linux-gnueabihf-gcc',
    'mips': 'mipsel-linux-gnu-gcc'
}

COMMON_OPTIONS = '-lcrypt -lcrypto -lssl ' \
    '-Itests/common/include ' \
    '-Wno-deprecated-declarations'

def compile_all():
    # If 'tests/common/include/openssl' dir does not exist
    # Extract OpenSSL header files from 'tests/common/include/openssl.tar.gz'
    common_dir = os.path.join('tests', 'common')
    lib_dir = os.path.join(common_dir, 'lib')
    include_dir = os.path.join(common_dir, 'include')
    openssl_include_dir = os.path.join(include_dir, 'openssl')
    if not os.path.exists(openssl_include_dir):
        tf = tarfile.open(openssl_include_dir + '.tar.gz')
        tf.extractall(include_dir)

    for filename in filter(lambda filename : filename.startswith('test_'), os.listdir('tests')):
        test_case_dir = os.path.join('tests', filename)
        if os.path.isdir(test_case_dir):
            dirs = map(lambda sub_dir : os.path.join(test_case_dir, sub_dir), 
                       ('bin', 'input', 'log', 'report', 'tmp'))
            bin_dir, input_dir, log_dir, report_dir, tmp_dir = dirs
            for dir in dirs:
                pathlib.Path.mkdir(pathlib.Path(dir), exist_ok=True)
                
            src_dir = os.path.join(test_case_dir, 'src')
            for src_file in filter(lambda filename : filename.endswith('.c'), os.listdir(src_dir)):
                for arch, compiler in COMPILERS.items():
                    lib_option = f'-L{os.path.join(lib_dir, arch)}'
                    output_dir = os.path.join(bin_dir, arch)
                    pathlib.Path.mkdir(pathlib.Path(output_dir), exist_ok=True)
                    output_path = os.path.join(output_dir, f'{os.path.splitext(src_file)[0]}')
                    src_path = os.path.join(src_dir, src_file)
                    os.system(f'{compiler} {src_path} -o {output_path} {lib_option} {COMMON_OPTIONS}')
                    squashfs_path = os.path.join(input_dir, f'{filename}_{arch}.bin')
                    pathlib.Path.unlink(pathlib.Path(squashfs_path), missing_ok=True)
                    os.system(f'mksquashfs {output_dir} {squashfs_path} -quiet')
                    
def build_suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromModule(tests))
    return suite

if __name__ == '__main__':
    compile_all()
    runner = unittest.TextTestRunner(verbosity=1)
    runner.run(build_suite())