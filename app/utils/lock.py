import os
import sys
import time
from pathlib import Path
from typing import Optional

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import msvcrt
else:
    import fcntl


class LockAcquisitionError(Exception):
    """Raised when acquiring a process file lock fails."""
    pass


class FileLock:
    """
    Cross-platform process file lock implementation.
    Uses msvcrt on Windows and fcntl on Linux/Unix.
    """

    def __init__(self, lock_file_path: Path):
        self.lock_file_path = Path(lock_file_path)
        self.file_obj = None
        self.is_locked = False

    def acquire(self, blocking: bool = False) -> bool:
        """
        Attempts to acquire an exclusive lock on the file.
        Returns True if acquired successfully, False if locked by another process.
        """
        if self.is_locked:
            return True

        self.lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Open file for reading/writing, creating if needed
            self.file_obj = open(self.lock_file_path, "a+")
            
            if IS_WINDOWS:
                # Seek to start for msvcrt locking
                self.file_obj.seek(0)
                fd = self.file_obj.fileno()
                mode = msvcrt.LK_NBLCK if not blocking else msvcrt.LK_LOCK
                # Lock 1 byte
                msvcrt.locking(fd, mode, 1)
            else:
                fd = self.file_obj.fileno()
                flags = fcntl.LOCK_EX
                if not blocking:
                    flags |= fcntl.LOCK_NB
                fcntl.flock(fd, flags)

            # Write current PID into lock file
            self.file_obj.seek(0)
            self.file_obj.truncate()
            self.file_obj.write(f"{os.getpid()}\n")
            self.file_obj.flush()
            self.is_locked = True
            return True

        except (IOError, OSError, PermissionError):
            if self.file_obj:
                try:
                    self.file_obj.close()
                except Exception:
                    pass
                self.file_obj = None
            self.is_locked = False
            return False

    def release(self) -> None:
        """Releases the lock and closes the file descriptor."""
        if not self.is_locked or self.file_obj is None:
            return

        try:
            fd = self.file_obj.fileno()
            if IS_WINDOWS:
                self.file_obj.seek(0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:
            pass
        finally:
            try:
                self.file_obj.close()
            except Exception:
                pass
            self.file_obj = None
            self.is_locked = False
            # Remove lock file if possible
            try:
                if self.lock_file_path.exists():
                    self.lock_file_path.unlink()
            except Exception:
                pass

    def __enter__(self):
        if not self.acquire(blocking=False):
            raise LockAcquisitionError(f"Could not acquire lock on {self.lock_file_path}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
