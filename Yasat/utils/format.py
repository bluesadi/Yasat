import traceback


def format_exception(e):
    return "".join(traceback.format_exception(type(e), e, e.__traceback__))


def format_stmt(stmt):
    return f"{hex(stmt.ins_addr)} | {stmt}"
