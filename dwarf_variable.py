

class Variable:

    def __init__(self, name, type_ref, decl_file, decl_line):
        self.name = name
        self.type_ref = type_ref
        self.decl_file = decl_file
        self.decl_line = decl_line

    def __repr__(self):
        return "<Variable @ %s>" % self.__str__()

    def __str__(self):
        return "%s %s" % (self.name, self.type_ref)
