from abc import ABC, abstractmethod

class Oracle(ABC):
    
    def __init__(self, config):
        self.calls = 0
        self.round_trips = 0
        self.config = config
        self.good = None
    
    @abstractmethod
    def query_raw(self, number):
        pass

    @abstractmethod
    def query(self, number):
        pass
    
    @abstractmethod
    def submit(self, work):
        pass
    
    @abstractmethod
    def cancel(self, work):
        pass
