import json

from ailment.statement import Statement

from .logger import default_logger


class PrintUtil:
    def pstr(obj):
        """
        Convert an object to a pretty Json string.

        :param obj: The object to be converted.
        """
        try:
            return str(json.dumps(obj, indent=2))
        except BaseException:
            default_logger.warning(f"Cannot convert {type(obj)} to Json format")
            return str(obj)

    def pstr_stmt(stmt: Statement):
        return f"{hex(stmt.ins_addr)} | {stmt}"
