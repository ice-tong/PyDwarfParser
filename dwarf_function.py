

class Function:

    def __init__(self, name, low_pc, high_pc, decl_file, decl_line,
                 frame_base=None, prototyped=None, call_sites=None):
        self.name = name
        self.low_pc = low_pc
        self.high_pc = high_pc
        self.decl_file = decl_file
        self.decl_line = decl_line
        self.frame_base = frame_base
        self.prototyped = prototyped
        self.call_sites = call_sites

    @property
    def address(self):
        return self.low_pc

    def __repr__(self):
        return "<Function @ %s %s>" % (self.name. self.address)

    def __str__(self):
        return self.__repr__()  # TODO
