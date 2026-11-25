"""HOST-only child output fixtures; never a native helper or device probe."""
import sys
import time


def output(text):
    sys.stdout.buffer.write(text.encode('ascii'))


def main():
    mode = sys.argv[1]
    if mode == 'valid':
        output('{"event":"capabilities","powered":true}\n')
    elif mode == 'nonzero':
        output('{"event":"capabilities","powered":true}\n')
        return 7
    elif mode == 'stderr':
        output('{"event":"capabilities","powered":true}\n')
        sys.stderr.buffer.write(b'HOST fixture warning\n')
    elif mode == 'invalid':
        output('{not-json}\n')
    elif mode == 'multiline':
        output('{"event":"capabilities"}\n{"event":"other"}\n')
    elif mode == 'oversize':
        output('x' * 16385 + '\n')
    elif mode == 'list':
        output('[]\n')
    elif mode == 'wait':
        output('HOST fixture before wait\n')
        sys.stdout.buffer.flush()
        time.sleep(15)
    else:
        raise ValueError('Unknown HOST fixture mode')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
