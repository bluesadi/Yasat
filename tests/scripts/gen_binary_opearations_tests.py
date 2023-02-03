import random

def rand32():
    return random.randint(0, 0xFFFFFFFF)

def add32(a, b):
    return (a + b) & 0xFFFFFFFF

BIN_OPS = [
    (add32, '+', 'int32_t')
]

if __name__ == '__main__':
    for func, op_name, var_type in BIN_OPS:
        correct_results = []
        func_name = func.__name__
        with open(f'../binaries_src/{func_name}.c', 'w') as fd:
            fd.write(f'#include <stdint.h>\n\n' \
                     f'void sink({var_type} a){{ }}\n\n' \
                     f'{var_type} {func_name}({var_type} a, {var_type} b){{\n\treturn a {op_name} b;\n}}\n\n'\
                     'int main(){\n')
            for i in range(100):
                a = rand32()
                b = rand32()
                correct_results.append(add32(a, b))
                fd.write(f'\tsink({func_name}({a}, {b}));\n')
            fd.write('}')
        
        with open(f'../test_{func_name}.py', 'w') as fd:
            fd.write('import angr\n\n'
                     f'def test_{func_name}():\n' \
                     f'\tproj = angr.Project()')