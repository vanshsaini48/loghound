import gzip
from contextlib import contextmanager


@contextmanager
def smart_open(file_path):
    """Open a file transparently — handles .gz compression."""
    if str(file_path).endswith('.gz'):
        f = gzip.open(file_path, 'rt')
    else:
        f = open(file_path)
    try:
        yield f
    finally:
        f.close()
