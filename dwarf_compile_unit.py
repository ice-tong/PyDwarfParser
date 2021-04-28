

class CompileUnit:

    def __init__(self, name, comp_dir, lang,
                 producer, low_pc, high_pc):
        self.name = name
        self.comp_dir = comp_dir
        self.lang = lang
        self.producer = producer
        self.low_pc = low_pc
        self.high_pc = high_pc

    def __repr__(self):
        return "<CompileUnit @ %s>" % self.name

    def __str__(self):
        return self.__repr__()  # TODO
