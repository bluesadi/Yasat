import json
import logging
import traceback

from ailment.statement import Statement

l = logging.getLogger(__name__)

class PrintUtil:
    def pstr(obj):
        """
        Convert an object to a pretty Json string.

        :param obj: The object to be converted.
        """
        if not isinstance(obj, dict):
            return str(obj)
        try:
            return str(json.dumps(obj, indent=2))
        except:
            l.warning(f"Cannot convert {type(obj)} to Json format")
            return str(obj)

    def pstr_stmt(stmt: Statement):
        return f"{hex(stmt.ins_addr)} | {stmt}"

    def format_exception(e):
        return "".join(traceback.format_exception(type(e), e, e.__traceback__))