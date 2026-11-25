# -*- coding: utf-8 -*-
"""Print a read-only stock baseline as a Python literal; no device files written."""
from safety import stock_snapshot


if __name__ == '__main__':
    print('RESULT=' + repr(stock_snapshot()))
