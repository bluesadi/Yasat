import angr
import cle
from time import time

path = '/home/bluesadi/Yasat/tmp/_freshtomato-RT-AC3200-ARM-2022.5-AIO-64K.trx.extracted/squashfs-root/usr/libexec/mysqld'
a = time()
loader = cle.Loader(path)
b = time()
proj = angr.Project(path)
c = time()

print(proj.kb.defs)