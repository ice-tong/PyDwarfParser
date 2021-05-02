

class VariableLocation:

    def __init__(self, sort, base, offset):
        """
        :param sort: bp, frame_base, register or global.
        :param base: the base of offset, usual is a register.
            in the case of global variable, base=0.
        :param offset: variable offset from base
        """
        self.sort = sort
        self.base = base
        self.offset = offset

    def __repr__(self):
        return "<VariableLocation @ %s>" % self.__str__()

    def __str__(self):
        if self.sort == "global":
            return "%s" % self.offset
        elif self.sort == "bp" and self.offset > 0:
            return "bp + %#x" % self.offset
        elif self.sort == "bp" and self.offset <= 0:
            return "bp - %#x" % abs(self.offset)
        elif self.sort == "frame_base" and self.offset > 0:
            return "frame_base + %#x" % self.offset
        elif self.sort == "frame_base" and self.offset <= 0:
            return "frame_base - %#x" % abs(self.offset)
        elif self.sort == "register" and self.offset == 0:
            return "reg%s" % self.base
        elif self.sort == "register" and self.offset > 0:
            return "reg%s + %#x" % (self.base, self.offset)
        elif self.sort == "register" and self.offset <= 0:
            return "reg%s - %#x" % (self.base, abs(self.offset))
        else:
            return "unknown"


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
        return "<%s @ name: %s, type: %s, location: %s>" % (
            prefix, self.name, self.type_ref, self.location)

    def __str__(self):
        return self.__repr__()  # TODO
