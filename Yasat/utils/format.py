import traceback

def format_exception(e):
    return "".join(traceback.format_exception(type(e), e, e.__traceback__))