class Config:
    input_path: str
    tmp_dir: str
    report_dir: str
    log_dir: str

    debug_mode: bool
    preprocess_timeout: int

    checkers: list

    def __init__(self, yaml_config):
        self._yaml_config = yaml_config

    def __getattr__(self, name):
        if name == "_yaml_config":
            return super().__getattr__(name)
        elif name in self._yaml_config:
            return self._yaml_config[name]
        raise AttributeError

    def __setattr__(self, __name, __value):
        if __name == "_yaml_config":
            super().__setattr__(__name, __value)
        else:
            self._yaml_config[__name] = __value

    def __str__(self) -> str:
        result = ""
        for attr in self._yaml_config:
            result += f"[-] {attr}: {self._yaml_config[attr]}\n"
        return result

    def __repr__(self) -> str:
        return self.__str__()
