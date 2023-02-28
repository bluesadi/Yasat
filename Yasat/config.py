from .utils.print import PrintUtil


class Config:
    input_path: str
    tmp_dir: str
    report_dir: str
    log_dir: str
    db_dir: str

    debug_mode: bool
    preprocess_timeout: int
    analyze_timeout: int

    checkers: list

    __slots__ = (
        "input_path",
        "tmp_dir",
        "report_dir",
        "log_dir",
        "db_dir",
        "debug_mode",
        "preprocess_timeout",
        "analyze_timeout",
        "checkers",
    )

    def __init__(self, yaml_config):
        for attr in self.__slots__:
            setattr(self, attr, yaml_config[attr])

    def __str__(self) -> str:
        result = ""
        for attr in self.__slots__:
            result += f"[-] {attr}: {PrintUtil.pstr(getattr(self, attr))}\n"
        return result

    def __repr__(self) -> str:
        return self.__str__()
