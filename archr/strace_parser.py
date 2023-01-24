"""Simple Strace-Style Log Entry Parser

The parser converts a string representing a strace-style log entry
into an object representing the log entry and syscall

Grammar
-------
    The highest level expression is a single strace log entry
    Each strace entry is composed of a NUMBER representing the PID followed
    by a syscall or syscall and an error message.

        strace_line : NUMBER syscall
        strace_line : NUMBER syscall error_message


    Syscalls can be represented by a few different forms.
    All forms look like a 'function call', starting with a SYMBOL (a alphanumeric word,
    starting with an alphabetical character) and has a set of parentheses.
    Sometimes a syscall has arguments (the 'arg_list'),
    and sometimes has a return value or a 'result'.

        syscall : SYMBOL LEFT_PAREN arg_list RIGHT_PAREN result
        syscall : SYMBOL LEFT_PAREN RIGHT_PAREN result
        syscall : SYMBOL LEFT_PAREN arg_list RIGHT_PAREN
        syscall : SYMBOL LEFT_PAREN RIGHT_PAREN


    An error message always takes the same form.
    This is the symbol 'errno' (ERRNO_S) followed by a result, and a message in parentheses.
    (captured as an arg_list)

        error_message : ERRNO_S result LEFT_PAREN arg_list RIGHT_PAREN


    A result starts with an equals sign and is followed by either a decimal or hexadecimal number

        result : EQUALS NUMBER
        result : EQUALS HEX_NUMBER


    An argument list is will be a mixed sequence of SYMBOLS, STRINGS, or numbers

        arg_list : arg_list SYMBOL
        arg_list : arg_list STRING
        arg_list : arg_list NUMBER
        arg_list : arg_list HEX_NUMBER
        arg_list : SYMBOL
        arg_list : STRING
        arg_list : NUMBER
        arg_list : HEX_NUMBER

Resources
---------
This parser is built on PLY (https://www.dabeaz.com/ply/)
The design is based on the tutorials by Andrew Dalke (www.dalkescientific.com/writings/NBN/parsing_with_ply.html)
"""

import logging

from ply import lex
from ply import yacc


l = logging.getLogger("archr.strace_parser")

tokens = (
    "SPACE",
    "NUMBER",
    "HEX_NUMBER",
    "RIGHT_PAREN",
    "LEFT_PAREN",
    "COMMA",
    "EQUALS",
    "SYMBOL",
    "ERRNO_S",
    "STRING",
)


def t_SPACE(t):  # pylint: disable=unused-argument
    r"\s+"


def t_HEX_NUMBER(t):
    r"0x[0-9a-f]+"
    t.value = int(t.value, 16)
    return t


def t_NUMBER(t):
    r"-*\d+"
    t.value = int(t.value)
    return t


t_LEFT_PAREN = r"\("
t_RIGHT_PAREN = r"\)"


def t_COMMA(t):  # pylint: disable=unused-argument
    r","


t_EQUALS = r"="

special_symbols = {
    "errno": "ERRNO_S",
}


def t_SYMBOL(t):
    r"[a-zA-Z_][a-zA-Z0-9_|]+"

    t.type = special_symbols.get(t.value, t.type)
    return t


def t_STRING(t):
    r"\".*\" "
    # lets strip the quotes
    t.value = t.value[1:-1]
    return t


def t_error(t):
    raise TypeError(f"Unknown text '{t.value}'")


lex.lex()


class StraceEntry:
    """StraceEntry
    a class used to record a strace log entry

    Attributes
    ----------
    pid : int
        the PID of the strace
    syscall : Syscall
        the object representing the syscall from the log entry
    error : Error
        the object representing an error caused by the syscall.
        None if there was no error
    """

    def __init__(self, pid, syscall, error):
        self.pid = pid
        self.syscall = syscall
        self.error = error

    def __repr__(self):
        return f"StraceEntry({self.pid},{self.syscall},{self.error})"


class Syscall:
    """Syscall
    a class used to record the syscall from an strace log entry

    Attributes
    ----------
    syscall : str
        the name of the syscall
    args : list
        a list of arguments passed to the syscall function
    result : int
        the return value of the syscall
    """

    def __init__(self, syscall, args, result):
        self.syscall = syscall
        self.args = args
        self.result = result

    def __eq__(self, other):
        if not isinstance(other, str):
            raise NotImplementedError

        return other == self.syscall

    def __repr__(self):
        return f"Syscall({self.syscall}, args={self.args}, result={self.result})"


class Error:
    """Error
    a class to record an error raised by a syscall logged in a strace entry

    Attributes
    ----------
    errno : int
        the error number
    message : str
        the error message string if there was one
        None otherwise
    """

    def __init__(self, errno, message):
        self.errno = errno
        self.message = message

    def __repr__(self):
        return f"ERROR({self.errno}, {self.message})"


def p_strace_line(p):
    """
    strace_line : NUMBER syscall
    strace_line : NUMBER syscall error_message
    """
    p[0] = StraceEntry(p[1], p[2], p[3] if len(p) > 3 else None)


def p_syscall(p):
    """
    syscall : SYMBOL LEFT_PAREN arg_list RIGHT_PAREN result
    syscall : SYMBOL LEFT_PAREN RIGHT_PAREN result
    syscall : SYMBOL LEFT_PAREN arg_list RIGHT_PAREN
    syscall : SYMBOL LEFT_PAREN RIGHT_PAREN
    syscall : SYMBOL SYMBOL NUMBER
    """
    if len(p) == 6:
        p[0] = Syscall(p[1], p[3], p[5])
    elif len(p) == 5:
        if isinstance(p[4], str):
            p[0] = Syscall(p[1], p[3], None)
        elif isinstance(p[4], int):
            p[0] = Syscall(p[1], None, p[4])
    else:
        if p[1] == "Unknown":
            p[0] = Syscall("unknown_" + str(p[3]), None, None)
        else:
            p[0] = Syscall(p[1], p[3], None)


def p_error_message(p):
    """
    error_message : ERRNO_S result LEFT_PAREN arg_list RIGHT_PAREN
    """
    p[0] = Error(p[2], " ".join(p[4]))


def p_result(p):
    """
    result : EQUALS NUMBER
    result : EQUALS HEX_NUMBER
    """
    p[0] = p[2]


def p_arg_list(p):
    """
    arg_list : arg_list SYMBOL
    arg_list : arg_list STRING
    arg_list : arg_list NUMBER
    arg_list : arg_list HEX_NUMBER
    arg_list : SYMBOL
    arg_list : STRING
    arg_list : NUMBER
    arg_list : HEX_NUMBER
    """
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1]
        p[0].append(p[2])


def p_error(p):
    print(f"Syntax error at '{p.value}'")


yacc.yacc(debug=False, write_tables=False, errorlog=yacc.NullLogger())


def parse(strace_log_lines):
    """
    the primary interface for the strace parser

    Parameters
    ----------
    strace_log_lines : list
        a list of strings representing log entries in an strace style format

    Returns
    -------
    list
        a list of StraceEntry objects
    """
    entries = []
    for line in strace_log_lines:
        entry = yacc.parse(line)
        l.debug(entry)
        entries.append(entry)

    return entries


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], encoding="utf-8") as log_f:
        print(parse(log_f.readlines()))
