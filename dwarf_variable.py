

class Variable:

    def __init__(self, name, type_ref, decl_file, decl_line,
                 is_parameter, location=None):
        self.name = name
        self.type_ref = type_ref
        self.decl_file = decl_file
        self.decl_line = decl_line
        self.location = location

        self.is_parameter = is_parameter

    def __repr__(self):
        prefix = "Parameter Variable" if self.is_parameter else "Variable"
        return "<%s @ name: %s, type: %s, size: %s>" % (
            prefix, self.name, self.type_ref, self.type_ref.byte_size)

    def __str__(self):
        return self.__repr__()  # TODO
