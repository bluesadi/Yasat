class Config:
    
    input_path: str
    tmp_dir: str
    report_dir: str
    log_dir: str
    
    debug_mode: bool
    preparation_timeout: int
    
    tasks: list
    
    def __init__(self, yaml_config):
        self.__yaml_config = yaml_config
        
    def __getattr__(self, name):
        if name in self.__yaml_config:
            return self.__yaml_config[name]
        else:
            raise AttributeError
        
    def __str__(self) -> str:
        result = ''
        for attr in self.__yaml_config:
            result += f'[-] {attr}: {self.__yaml_config[attr]}\n'
        return result
    
    def __repr__(self) -> str:
        return self.__str__()