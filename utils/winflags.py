"""
winflags.py
author: gum3t

Contains a pool of windows related flags for instruction generation improvements.
"""
from typing import List

NULL: int                       = 0x0
GENERIC_ALL: int                = 0x10000000
GENERIC_EXECUTE: int            = 0x20000000
GENERIC_WRITE: int              = 0x40000000
GENERIC_READ: int               = 0x80000000
FILE_SHARE_READ: int            = 0x00000001
FILE_SHARE_WRITE: int           = 0x00000002
CREATE_NEW: int                 = 0x1
CREATE_ALWAYS: int              = 0x2
OPEN_NEW: int                   = 0x3
OPEN_ALWAYS: int                = 0x4
TRUNCATE_EXISTING: int          = 0x5
FILE_ATTRIBUTE_NORMAL: int      = 0x80
CREATE_SUSPENDED: int           = 0x00000004
CREATE_NEW_CONSOLE: int         = 0x00000010
CREATE_NO_WINDOW: int           = 0x08000000
DETACHED_PROCESS: int           = 0x00000008
PAGE_READONLY: int              = 0x02
PAGE_READWRITE: int             = 0x04
PAGE_EXECUTE_READ: int          = 0x20
PAGE_EXECUTE_READWRITE: int     = 0x40
THREAD_QUERY_INFORMATION: int   = 0x0040
THREAD_SUSPEND_RESUME: int      = 0x0002
WS_OVERLAPPEDWINDOW: int        = 0x00CF0000
WS_VISIBLE: int                 = 0x10000000
WS_CHILD: int                   = 0x40000000
WS_BORDER: int                  = 0x00800000
WS_CAPTION: int                 = 0x00C00000


winflags: List[int] = [
    NULL,                       
    GENERIC_ALL,
    GENERIC_EXECUTE,
    GENERIC_WRITE,
    GENERIC_READ,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    CREATE_NEW,
    CREATE_ALWAYS,
    OPEN_NEW,
    OPEN_ALWAYS,
    TRUNCATE_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    CREATE_SUSPENDED,
    CREATE_NEW_CONSOLE,
    CREATE_NO_WINDOW,
    DETACHED_PROCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME,
    WS_OVERLAPPEDWINDOW,
    WS_VISIBLE,
    WS_CHILD,
    WS_BORDER,
    WS_CAPTION
]              