import time

class Timer:
    
    def __init__(self):
        self.start_time = 0
        self.last_time = 0
        
    def start(self):
        self.start_time = time.time()
        self.last_time = self.start_time
        
    @property
    def interval(self):
        cur_time = time.time()
        last_time = self.last_time
        self.last_time = cur_time
        return format(cur_time - last_time, '.1f')
    
    @property
    def total(self):
        return format(time.time() - self.init_time, '.1f')