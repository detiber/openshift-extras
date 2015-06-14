class HostConfigError(Exception)
    pass


class HostConfig(object):

    def __init__(self):
        pass

    def from_facts(self):
        pass

    def from_yaml(self):
        pass

    def to_yaml(self):
        pass

    def __str__(self):
        return self.to_yaml()
