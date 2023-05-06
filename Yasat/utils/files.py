import os
import shutil
import pathlib


class Files:
    @staticmethod
    def join(*paths):
        return os.path.normpath(os.path.join(*paths))

    @staticmethod
    def remove(*paths):
        for path in paths:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                pathlib.Path(path).unlink(missing_ok=True)

    @staticmethod
    def mkdirs(*paths):
        for path in paths:
            pathlib.Path(path).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def clear(*paths):
        Files.remove(*paths)
        Files.mkdirs(*paths)
