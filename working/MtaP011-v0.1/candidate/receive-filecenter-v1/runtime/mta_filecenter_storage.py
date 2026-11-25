"""Retained-open adaptation of the original confined Toolbox FileStore.

Directory/path policy and listing/text are inherited unchanged. Each numeric
FD is retained before fstat/fdopen; uncertain wrapping is never blindly closed.
"""
import errno
import os
import stat
from mta_toolbox_storage import FileStore, components, native_name


def fd_closed(fd):
    try: os.fstat(fd)
    except OSError as error: return error.errno == errno.EBADF
    return False


class _Reader:
    def __init__(self, row): self.row = row
    @property
    def closed(self): return self.row['handle'].closed
    def fileno(self): return self.row['handle'].fileno()
    def read(self, size=-1): return self.row['handle'].read(size)
    def seek(self, *args): return self.row['handle'].seek(*args)
    def close(self):
        row = self.row
        if row['close_called']: return
        row['close_called'] = True
        try: row['handle'].close()
        except BaseException as error: row['close_error'] = error; raise
        row['closed'] = row['handle'].closed is True
    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class RetainedFileStore(FileStore):
    def __init__(self, root):
        self.open_rows = []
        FileStore.__init__(self, root)

    def open_file(self, path):
        parts = components(path)
        if len(parts) < 2: raise ValueError('请选择用户文件')
        row = dict(parent=None, parent_returned=False, parent_closed=False,
            called=False, returned=False, fd=None, handle=None, proxy=None,
            wrapping=False, wrap_unknown=False, close_called=False, closed=False,
            error=None, close_error=None)
        self.open_rows.append(row)
        try:
            parent = self.directory(parts[:-1]); row['parent'] = parent
            row['parent_returned'] = True
            flags = os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_NONBLOCK',0)
            if not self.fd_mode and os.path.islink(os.path.join(parent,parts[-1])):
                raise ValueError('禁止链接')
            row['called'] = True
            try:
                row['fd'] = (os.open(native_name(parts[-1]),flags,dir_fd=parent) if self.fd_mode else
                    os.open(native_name(os.path.join(parent,parts[-1])),flags))
            except OSError as error:
                if type(error.errno) is int and 1 <= error.errno <= 4095: row['closed'] = True
                raise
            row['returned'] = True
            info = os.fstat(row['fd'])
            if not stat.S_ISREG(info.st_mode): raise ValueError('不是普通文件')
            row['wrapping'] = row['wrap_unknown'] = True
            row['handle'] = os.fdopen(row['fd'],'rb')
            row['wrap_unknown'] = False
            row['proxy'] = _Reader(row)
            return row['proxy'], info
        except BaseException as error:
            row['error'] = error
            if row['handle'] is not None:
                row['close_called'] = True
                try: row['handle'].close(); row['closed'] = row['handle'].closed is True
                except BaseException as close_error: row['close_error'] = close_error
            elif row['returned'] and not row['wrap_unknown']:
                row['close_called'] = True
                try: os.close(row['fd']); row['closed'] = fd_closed(row['fd'])
                except BaseException as close_error: row['close_error'] = close_error
            elif row['wrap_unknown'] and fd_closed(row['fd']):
                # Still an uncertain fdopen outcome, but no numeric FD remains.
                row['closed'] = True
            elif not row['called']: row['closed'] = True
            raise
        finally:
            if row['parent_returned']:
                try: self.release(row['parent']); row['parent_closed'] = True
                except BaseException as close_error: row['close_error'] = close_error

    def close_known_opens(self):
        for row in self.open_rows:
            if row['handle'] is not None and row['handle'].closed is False:
                if row['proxy'] is not None: row['proxy'].close()
                elif not row['close_called']:
                    row['close_called'] = True; row['handle'].close(); row['closed'] = row['handle'].closed is True

    def opens_closed(self):
        return all(row['closed'] and not row['wrap_unknown'] and
            (not row['parent_returned'] or row['parent_closed']) and row['close_error'] is None and
            (row['handle'] is None or row['handle'].closed is True) for row in self.open_rows)
