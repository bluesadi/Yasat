from ailment.statement import Statement

def stmt_to_str(stmt: Statement, stmt_idx=None):
    if stmt_idx is not None:
        return f'{str(stmt_idx).zfill(2)} | {hex(stmt.ins_addr)} | {stmt}'
    else:
        return f'{hex(stmt.ins_addr)} | {stmt}'