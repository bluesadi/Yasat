from typing import Callable
import traceback
import logging

from func_timeout import func_timeout
from func_timeout.exceptions import FunctionTimedOut

l = logging.getLogger(__name__)


class TimeoutUtil:
    def call_with_timeout(func: Callable, args, timeout):
        try:
            return func_timeout(timeout, func, args=args)
        except FunctionTimedOut as e:
            l.warning(
                f"Function {func.__name__} timed out after {e.timedOutAfter} seconds"
            )
        except:
            l.error(f"Error occured when executing function {func.__name__}")
            l.error(traceback.format_exc())
        return None
