"""File reader with optional progress tracking."""
import os
import sys
from contextlib import contextmanager
import gzip


@contextmanager
def smart_open(file_path, show_progress=False):
    """Open a file transparently — handles .gz compression.
    
    If show_progress=True, print periodic byte-count updates to stderr.
    """
    file_path = str(file_path)
    is_gz = file_path.endswith('.gz')
    
    if is_gz:
        f = gzip.open(file_path, 'rt')
    else:
        f = open(file_path)
    
    if not show_progress:
        try:
            yield f
        finally:
            f.close()
    else:
        # Wrap with progress tracking
        try:
            total_bytes = os.path.getsize(file_path)
            wrapped = _ProgressFile(f, total_bytes)
            yield wrapped
        finally:
            f.close()


class _ProgressFile:
    """File-like wrapper that tracks bytes read and prints progress."""
    
    PROGRESS_INTERVAL = 1024 * 1024  # Print every 1 MB
    
    def __init__(self, f, total_bytes):
        self.f = f
        self.total_bytes = total_bytes
        self.bytes_read = 0
        self.last_report = 0
    
    def readline(self):
        line = self.f.readline()
        if line:
            self.bytes_read += len(line.encode('utf-8')) if isinstance(line, str) else len(line)
            if self.bytes_read - self.last_report >= self.PROGRESS_INTERVAL:
                self._print_progress()
                self.last_report = self.bytes_read
        else:
            # End of file: final progress
            self._print_progress()
        return line
    
    def __iter__(self):
        return self
    
    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line
    
    def _print_progress(self):
        mb_read = self.bytes_read / (1024 * 1024)
        mb_total = self.total_bytes / (1024 * 1024)
        pct = int(100 * self.bytes_read / self.total_bytes) if self.total_bytes > 0 else 0
        print(
            f"\r[parsing...] {mb_read:.1f} / {mb_total:.1f} MB ({pct}%)",
            end="",
            file=sys.stderr,
            flush=True,
        )
    
    def close(self):
        # Ensure final newline on stderr
        print("", file=sys.stderr)
        self.f.close()
