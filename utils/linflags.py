"""
linflags.py
author: gum3t

Contains a pool of linux related flags for instruction generation improvements.
"""
from typing import List

NULL: int           = 0x0
O_RDONLY: int       = 0x00000000
O_WRONLY: int       = 0x00000001
O_RDWR: int         = 0x00000002
O_CREAT: int        = 0x00000100
O_EXCL: int         = 0x00000200
O_TRUNC: int        = 0x00001000
O_APPEND: int       = 0x00002000
O_NONBLOCK: int     = 0x00004000
O_SYNC: int         = 0x04000000
PROT_READ: int      = 0x1
PROT_WRITE: int     = 0x2
PROT_EXEC: int      = 0x4
MAP_SHARED: int     = 0x01
MAP_PRIVATE: int    = 0x02
MAP_ANONYMOUS: int  = 0x10
SA_RESTART: int     = 0x00000002
SA_NOCLDWAIT: int   = 0x00000020
SA_SIGINFO: int     = 0x00000040
SOCK_DGRAM: int     = 0x1
SOCK_STREAM: int    = 0x2
SOCK_RAW: int       = 0x3
MSG_PEEK: int       = 0x2
MSG_DONTWAIT: int   = 0x40
EPOLLIN: int        = 0x00000001
EPOLLOUT: int       = 0x00000004
EPOLLERR: int       = 0x00000008


linflags: List[int] = [
    NULL,
    O_RDONLY,      
    O_WRONLY,
    O_RDWR,       
    O_CREAT,     
    O_EXCL,
    O_TRUNC,
    O_APPEND,
    O_NONBLOCK,
    O_SYNC,
    PROT_READ,
    PROT_WRITE,
    PROT_EXEC,
    MAP_SHARED,
    MAP_PRIVATE,
    MAP_ANONYMOUS,
    SA_RESTART,
    SA_NOCLDWAIT,
    SA_SIGINFO,
    SOCK_DGRAM,
	SOCK_STREAM,
	SOCK_RAW,
    MSG_PEEK,
    MSG_DONTWAIT,
    EPOLLIN,
    EPOLLOUT,
    EPOLLERR
]