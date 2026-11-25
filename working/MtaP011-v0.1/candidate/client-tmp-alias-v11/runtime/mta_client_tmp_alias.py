"""Fixed observed tmp aliases; directory facts ONLY, never RF/owner authority.

Construction is pure. Every open is delegated to the caller's registered
original-resource inventory. This object never opens/closes an FD itself.
Only /tmp -> /var/tmp -> /var/volatile/tmp is supported, not general namei.
"""
import stat

PHYSICAL_TMP = '/var/volatile/tmp'
_CODES = frozenset(('invalid_context', 'already_attempted', 'not_prepared',
    'already_bound', 'not_bound', 'unsafe_directory', 'alias_changed',
    'directory_changed', 'invalid_descriptor', 'invalid_ticket', 'io_error',
    'observation_unknown'))


class TmpAliasError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'io_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise TmpAliasError(code) from None


def _uint(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 <= value <= maximum


def _meta(value):
    result = tuple(getattr(value, key, None) for key in
        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(not _uint(v) for v in result): _fail('observation_unknown')
    return result


def _directory(value, mode=None):
    row = _meta(value)
    if not stat.S_ISDIR(row[2]) or row[3:5] != (0, 0) or row[5] < 1:
        _fail('unsafe_directory')
    if mode is None:
        if stat.S_IMODE(row[2]) & 0o022: _fail('unsafe_directory')
    elif stat.S_IMODE(row[2]) != mode:
        _fail('unsafe_directory')
    # Normal entry updates may change directory times/size/link count.
    return row[:5]


class FixedTmpAnchor(object):
    """Caller-owned tickets, fixed profile, sticky unknown state.

    fd_of(ticket) must verify that exact caller-original ticket is live/known.
    open_dir(parent_ticket, fixed_name) must register BEFORE the actual open,
    use NOFOLLOW|DIRECTORY|CLOEXEC, and retain partial/unknown original returns.
    check() uses the caller's existing finite monotonic operation budget.
    The caller stores this exact object in its private _tmp_alias slot before
    prepare. Returned self is a path observation, not a Boolean permission.
    """
    def __init__(self, owner, io, root_ticket, fd_of, open_dir, check):
        if owner is None or io is None or root_ticket is None or any(
                not callable(c) for c in (fd_of, open_dir, check)):
            _fail('invalid_context')
        self._context = (owner, io, root_ticket, fd_of, open_dir, check)
        self._attempted = self._prepared = self._bound = self._unknown = False
        self._var = self._volatile = self._tmp = None
        self._identities, self._aliases = (), ()

    def __repr__(self): return '<fixed CLIENT tmp path observation>'

    @property
    def prefix_tickets(self):
        return tuple(t for t in (self._var, self._volatile) if t is not None)

    @property
    def tmp_parent(self):
        if not self._prepared or self._unknown: _fail('not_prepared')
        return self._volatile

    @property
    def tmp_ticket(self): return self._tmp

    def _guard(self, owner, root):
        c = self._context
        if owner is not c[0] or root is not c[2] or getattr(owner, '_io', None) is not c[1] or \
                getattr(owner, '_tmp_alias', None) is not self:
            _fail('invalid_context')
        if self._unknown: _fail('observation_unknown')
        c[5]()

    def _fd(self, ticket):
        self._context[5]()
        value = self._context[3](ticket)
        if not _uint(value, 0x7fffffff): _fail('invalid_descriptor')
        return value

    def _alias(self, parent, target):
        io, check = self._context[1], self._context[5]
        fd = self._fd(parent)
        check(); before = _meta(io.stat_at(fd, 'tmp'))
        if not stat.S_ISLNK(before[2]) or before[3:5] != (0, 0) or \
                stat.S_IMODE(before[2]) != 0o777 or before[5] != 1 or before[6] != len(target):
            _fail('alias_changed')
        check(); text = io.readlink_at(fd, 'tmp')
        check(); after = _meta(io.stat_at(fd, 'tmp'))
        if type(text) is not str or text != target or after != before:
            _fail('alias_changed')
        return before, text

    def _open_prefix(self, parent, name, mode):
        io, check, open_dir = self._context[1], self._context[5], self._context[4]
        parent_fd = self._fd(parent)
        check(); before = _directory(io.stat_at(parent_fd, name), mode)
        ticket = open_dir(parent, name)
        # Retain the exact callback return BEFORE any validation/readback.
        if name == 'var': self._var = ticket
        else: self._volatile = ticket
        if ticket is None or any(ticket is t for t in (self._context[2], self._var if name != 'var' else None)):
            _fail('invalid_ticket')
        fd = self._fd(ticket)
        if fd in tuple(self._fd(t) for t in (self._context[2], self._var) if t is not None and t is not ticket):
            _fail('invalid_descriptor')
        check(); actual = _directory(io.fstat(fd), mode)
        check(); current = _directory(io.stat_at(parent_fd, name), mode)
        if before != actual or actual != current: _fail('directory_changed')
        return actual

    def prepare(self):
        if self._attempted: _fail('already_attempted')
        self._attempted = True
        c = self._context
        try:
            self._guard(c[0], c[2])
            root = _directory(c[1].fstat(self._fd(c[2])))
            c[5]()
            if _directory(c[1].stat_root()) != root: _fail('directory_changed')
            first = self._alias(c[2], '/var/tmp')
            var = self._open_prefix(c[2], 'var', 0o755)
            second = self._alias(self._var, PHYSICAL_TMP)
            volatile = self._open_prefix(self._var, 'volatile', 0o1777)
            c[5](); _directory(c[1].stat_at(self._fd(self._volatile), 'tmp'), 0o1777)
            self._identities = (root, var, volatile)
            self._aliases = (first, second)
            self._prepared = True
            self._authenticate_prefix()
            return self
        except BaseException:
            self._unknown = True
            raise

    def _authenticate_prefix(self):
        c = self._context
        self._guard(c[0], c[2])
        if not self._prepared or len(self._identities) not in (3, 4): _fail('not_prepared')
        rows = ((c[2], None, None, None), (self._var, c[2], 'var', 0o755),
                (self._volatile, self._var, 'volatile', 0o1777))
        for index, (ticket, parent, name, mode) in enumerate(rows):
            c[5](); actual = _directory(c[1].fstat(self._fd(ticket)), mode)
            if actual != self._identities[index]: _fail('directory_changed')
            if parent is None:
                c[5]()
                if _directory(c[1].stat_root()) != actual: _fail('directory_changed')
            if parent is not None:
                c[5](); entry = _directory(c[1].stat_at(self._fd(parent), name), mode)
                if entry != actual: _fail('directory_changed')
        if (self._alias(c[2], '/var/tmp'), self._alias(self._var, PHYSICAL_TMP)) != self._aliases:
            _fail('alias_changed')

    def bind_tmp(self, original_ticket):
        if self._bound: _fail('already_bound')
        self._bound, self._tmp = True, original_ticket
        try:
            self._authenticate_prefix()
            if original_ticket is None or any(original_ticket is t for t in
                    (self._context[2], self._var, self._volatile)): _fail('invalid_ticket')
            fd = self._fd(original_ticket)
            if fd in tuple(self._fd(t) for t in (self._context[2], self._var, self._volatile)):
                _fail('invalid_descriptor')
            io, check = self._context[1], self._context[5]
            check(); actual = _directory(io.fstat(fd), 0o1777)
            check(); entry = _directory(io.stat_at(self._fd(self._volatile), 'tmp'), 0o1777)
            if actual != entry: _fail('directory_changed')
            self._identities += (actual,)
            return self.authenticate(self._context[0], self._context[2])
        except BaseException:
            self._unknown = True
            raise

    def authenticate(self, exact_owner, exact_root_ticket):
        try:
            self._guard(exact_owner, exact_root_ticket)
            if not self._bound or self._tmp is None: _fail('not_bound')
            self._authenticate_prefix()
            c = self._context
            c[5](); actual = _directory(c[1].fstat(self._fd(self._tmp)), 0o1777)
            c[5](); entry = _directory(c[1].stat_at(self._fd(self._volatile), 'tmp'), 0o1777)
            if actual != self._identities[3] or entry != actual: _fail('directory_changed')
            return self
        except BaseException:
            self._unknown = True
            raise
