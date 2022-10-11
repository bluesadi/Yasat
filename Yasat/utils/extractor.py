import os

# Load, decompress and extract firmware from `from_path` (dir/zip/binary),
# save them to `to_path`, and return a list of paths of libraries/executables
def extract(from_path, to_path):
    for root, _, files in os.walk(from_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(file_path)