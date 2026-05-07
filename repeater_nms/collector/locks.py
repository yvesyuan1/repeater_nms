from __future__ import annotations

from pathlib import Path


class CollectorInstanceLock:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = None

    def acquire(self) -> None:
        self.handle = self.path.open("a+")
        self.handle.seek(0)
        try:
            import fcntl

            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ModuleNotFoundError:
            import msvcrt

            try:
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError(f"collector instance lock already held: {self.path}") from exc
        except OSError as exc:
            raise RuntimeError(f"collector instance lock already held: {self.path}") from exc
        self.handle.truncate(0)
        self.handle.write("locked\n")
        self.handle.flush()

    def release(self) -> None:
        if self.handle is None:
            return
        try:
            import fcntl

            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        except ModuleNotFoundError:
            import msvcrt

            try:
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        finally:
            self.handle.close()
            self.handle = None

    def __enter__(self) -> "CollectorInstanceLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

