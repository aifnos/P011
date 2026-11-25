"""Anonymous first-cause notes only; no IO, query, close or admission authority."""
import builtins
import re


_V17_BUILTINS = tuple((name, getattr(builtins, name)) for name in (
    'OSError', 'BlockingIOError', 'BrokenPipeError', 'ChildProcessError',
    'ConnectionError', 'ConnectionAbortedError', 'ConnectionRefusedError',
    'ConnectionResetError', 'FileExistsError', 'FileNotFoundError',
    'InterruptedError', 'IsADirectoryError', 'NotADirectoryError',
    'PermissionError', 'ProcessLookupError', 'TimeoutError', 'ValueError',
    'TypeError', 'RuntimeError', 'MemoryError', 'OverflowError',
    'ArithmeticError', 'AssertionError', 'AttributeError', 'BufferError',
    'EOFError', 'FloatingPointError', 'ImportError', 'IndexError', 'KeyError',
    'LookupError', 'NameError', 'NotImplementedError', 'RecursionError',
    'ReferenceError', 'StopIteration', 'StopAsyncIteration', 'SyntaxError',
    'IndentationError', 'TabError', 'UnboundLocalError', 'UnicodeError',
    'UnicodeDecodeError', 'UnicodeEncodeError', 'UnicodeTranslateError',
    'ZeroDivisionError', 'Warning', 'UserWarning', 'DeprecationWarning',
    'PendingDeprecationWarning', 'SyntaxWarning', 'RuntimeWarning',
    'FutureWarning', 'ImportWarning', 'UnicodeWarning', 'BytesWarning',
    'ResourceWarning',
    'KeyboardInterrupt', 'SystemExit', 'GeneratorExit', 'Exception',
    'BaseException'))


def _v17_family(path, files):
    if type(path) is not str: return 'not_available'
    match = re.fullmatch('/proc/[1-9][0-9]*/(comm|cmdline|status|exe)', path)
    if match is not None: return 'proc_' + match.group(1)
    if path == '/proc': return 'proc_directory'
    if path == '/proc/net/unix': return 'proc_net_unix'
    if path == '/proc/config.gz': return 'proc_config'
    if path == files._manifest[0][0]: return 'daemon_image'
    if path.startswith('/proc/'): return 'proc_other'
    return 'other'


def _v17_record(files, error, phase, path, prior_count):
    """Retain the exact first error before formatting; never replace its raise."""
    try:
        if getattr(files, '_v17_first_error', None) is not None: return
        files._v17_first_error = error
        files._v17_note_unknown = True
        name = next((name for name, cls in _V17_BUILTINS if type(error) is cls), 'NON_BUILTIN')
        number = getattr(error, 'errno', None) if name != 'NON_BUILTIN' and isinstance(error, OSError) else None
        number = number if type(number) is int and 0 <= number <= 4095 else None
        if path is None and name != 'NON_BUILTIN' and isinstance(error, OSError):
            path = getattr(error, 'filename', None)
        row = None
        ordinal = None
        if type(prior_count) is int and len(files._tickets) == prior_count + 1:
            row, ordinal = files._tickets[prior_count], prior_count + 1
        files._v17_first_row = row  # exact original ticket, not a copied FD/closed bool
        files._v17_first_cause = {'builtin_class': name, 'errno': number,
            'phase': phase, 'path_family': _v17_family(path, files),
            'ticket_ordinal': ordinal}
        files._v17_note_unknown = False
    except BaseException:
        # Diagnostic allocation/formatting must not mask the original exception.
        try: files._v17_note_unknown = True
        except BaseException: pass


def _v17_project(files):
    if getattr(files, '_v17_first_error', None) is None: return None
    value = getattr(files, '_v17_first_cause', None)
    if value is None:
        return {'builtin_class': 'NOT_AVAILABLE', 'errno': None,
            'phase': 'not_available', 'path_family': 'not_available',
            'ticket_ordinal': None, 'note_unknown': True}
    result = dict(value)
    ordinal = result['ticket_ordinal']
    member = ordinal is None or type(ordinal) is int and 1 <= ordinal <= len(files._tickets) and \
        files._tickets[ordinal - 1] is files._v17_first_row
    result['note_unknown'] = getattr(files, '_v17_note_unknown', True) is not False or not member
    if not member: result['ticket_ordinal'] = None
    return result


def _v17_install(status, method_code):
    """Install notes on the already loaded exact 19-graph source classes once."""
    if getattr(status, '_v17_installed', False): raise ValueError('notes_once')
    original_open = status._ReadFiles._open
    original_read = status._ReadFiles._read_file

    def open_note(files, *args, **kwargs):
        count = len(files._tickets)
        try:
            return original_open(files, *args, **kwargs)
        except BaseException as caught:
            path = args[0] if args else kwargs.get('path')
            _v17_record(files, caught, 'file_open', path, count)
            raise

    def read_note(files, *args, **kwargs):
        count = len(files._tickets)
        try:
            return original_read(files, *args, **kwargs)
        except BaseException as caught:
            path = args[0] if args else kwargs.get('path')
            _v17_record(files, caught, 'file_read', path, count)
            raise

    status._v17_record = _v17_record
    exec(compile(method_code, '<v17-fixed-source-first-cause>', 'exec'), status.__dict__)
    status._ReadFiles._open = open_note
    status._ReadFiles._read_file = read_note
    status.LinuxStatusSource.read_source = status._v17_read_source
    status._v17_installed = True
