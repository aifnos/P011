"""Retained-open adaptation of the original confined Toolbox FileStore.

Directory/path policy and listing/text are inherited unchanged. Each numeric
FD is retained before fstat/fdopen; uncertain wrapping is never blindly closed.
"""
import errno
import os
import stat
import types
from mta_toolbox_storage import FileStore, components, native_name


def fd_closed(fd):
    try: os.fstat(fd)
    except OSError as error: return error.errno == errno.EBADF
    return False


def _close_metadata(value):
    result = tuple(getattr(value, name, None) for name in
        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(item) is not int or not 0 <= item < (1 << 64) for item in result):
        raise ValueError('filecenter_root_metadata_unknown')
    return result


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
        self.root_constructed = self.root_close_called = False
        self.root_close_return_none = None
        self.root_close_error = None
        self._root_close_original = self._root_close_original_retained = None
        self.root_close_seal = self._root_close_seal_retained = None
        self.root_close_methods = self._root_close_methods_retained = (
            type(self)._root_receipt, type(self).root_closed)
        try:
            FileStore.__init__(self, root)
            self.root_constructed = True
        except BaseException:
            try: self._retain_root()
            except BaseException as error: self.root_close_error = error
            raise
        self._retain_root()

    def _retain_root(self):
        fd = getattr(self, 'rootfd', None)
        original = (self, fd, None, FileStore.close)
        self._root_close_original = self._root_close_original_retained = original
        if fd is not None:
            if type(fd) is not int or fd < 0: raise ValueError('filecenter_root_unknown')
            metadata = _close_metadata(os.fstat(fd))
            if not stat.S_ISDIR(metadata[2]): raise ValueError('filecenter_root_unknown')
            original = (self, fd, metadata, FileStore.close)
            self._root_close_original = self._root_close_original_retained = original

    def _root_receipt(self):
        original = self._root_close_original
        if (type(original) is not tuple or len(original) != 4 or
                original is not self._root_close_original_retained or original[0] is not self or
                type(original[3]) is not types.FunctionType or FileStore.close is not original[3]):
            return None
        if original[1] is None:
            if original[2] is not None or self.root_constructed is not True or self.fd_mode is not False:
                return None
        elif (type(original[1]) is not int or original[1] < 0 or type(original[2]) is not tuple or
                len(original[2]) != 7 or any(type(item) is not int or item < 0 for item in original[2]) or
                not stat.S_ISDIR(original[2][2])):
            return None
        return original

    def root_closed(self):
        """Consume one actual close seal; never inspect the historical FD again."""
        methods = self.root_close_methods
        if (type(methods) is not tuple or methods is not self._root_close_methods_retained or
                len(methods) != 2 or type(self)._root_receipt is not methods[0] or
                type(self).root_closed is not methods[1]): return False
        original = methods[0](self)
        seal = self.root_close_seal
        if (original is None or self.root_constructed is not True or self.root_close_called is not True or
                self.root_close_error is not None or self.root_close_return_none is not True or
                self.rootfd is not None or type(seal) is not tuple or len(seal) != 6 or
                seal is not self._root_close_seal_retained or seal[0] is not original or
                seal[1] is not True or seal[2] is not True): return False
        if seal[3] == 'absent':
            return original[1] is None and seal[4] is None and seal[5] is None
        if original[1] is None: return False
        if seal[3] == 'badfd':
            return seal[4] is None and type(seal[5]) is int and seal[5] == errno.EBADF
        if seal[3] == 'reused':
            post = seal[4]
            return (type(post) is tuple and len(post) == 7 and
                all(type(item) is int and item >= 0 for item in post) and seal[5] is None and
                (post[0], post[1], stat.S_IFMT(post[2])) !=
                (original[2][0], original[2][1], stat.S_IFMT(original[2][2])))
        return False

    def close(self):
        if self.root_close_called:
            if self.root_closed(): return None
            if self.root_close_error is not None: raise self.root_close_error
            raise ValueError('filecenter_root_close_unknown')
        self.root_close_called = True
        try:
            methods = self.root_close_methods
            if (type(methods) is not tuple or methods is not self._root_close_methods_retained or
                    len(methods) != 2 or type(self)._root_receipt is not methods[0] or
                    type(self).root_closed is not methods[1]):
                raise ValueError('filecenter_root_close_unknown')
            original = methods[0](self)
            if original is None or self.rootfd is not original[1]:
                raise ValueError('filecenter_root_close_unknown')
            if original[1] is not None and _close_metadata(os.fstat(original[1]))[:5] != original[2][:5]:
                raise ValueError('filecenter_root_close_unknown')
            returned = original[3](self)
            self.root_close_return_none = returned is None
            if not self.root_close_return_none or self.rootfd is not None:
                raise ValueError('filecenter_root_close_unknown')
            post, number, outcome = None, None, 'absent'
            if original[1] is not None:
                try: post = _close_metadata(os.fstat(original[1]))
                except OSError as error:
                    number = error.errno
                    if type(number) is not int or number != errno.EBADF: raise
                    outcome = 'badfd'
                else:
                    if ((post[0], post[1], stat.S_IFMT(post[2])) ==
                            (original[2][0], original[2][1], stat.S_IFMT(original[2][2]))):
                        raise ValueError('filecenter_root_close_unknown')
                    outcome = 'reused'
            seal = (original, True, True, outcome, post, number)
            self.root_close_seal = self._root_close_seal_retained = seal
        except BaseException as error:
            self.root_close_error = error
            raise

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
