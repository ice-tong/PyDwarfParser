

__all__ = ["BaseType", "VolatileType", "ConstType", "TypeDef", "PointerType"]
__all__ += ["ArrayType", "EnumsType", "Structure", "Member", "Subroutine"]


class BaseType:

    def __init__(self, name, byte_size, enconding):
        self.name = name
        self.byte_size = byte_size
        self.enconding = enconding

    def __repr__(self):
        return "<BaseType @ %s %s %s>" % (
            self.name, self.byte_size, self.enconding)

    def __str__(self):
        return self.name


class ConstType:

    def __init__(self, type_ref):
        self.type_ref = type_ref

    @property
    def byte_size(self):
        return self.type_ref.byte_size

    def __repr__(self):
        return "<ConstType @ %s>" % self.__str__()

    def __str__(self):
        return "%s const" % self.type_ref


class VolatileType:

    def __init__(self, type_ref):
        self.type_ref = type_ref

    @property
    def byte_size(self):
        return self.type_ref.byte_size

    def __repr__(self):
        return "<VolatileType @ %s>" % self.__str__()

    def __str__(self):
        return "%s volatile" % self.type_ref


class TypeDef:

    def __init__(self, name, type_ref, decl_file, decl_line):
        """
        :param type_ref A type reference offset, -1 stands void?
        """
        self.name = name
        self.type_ref = type_ref
        self.decl_file = decl_file
        self.decl_line = decl_line

    @property
    def byte_size(self):
        return self.type_ref.byte_size

    def __repr__(self):
        return "<TypeDef @ %s>" % self.__str__()

    def __str__(self):
        return "%s" % self.name


class PointerType:

    def __init__(self, type_ref, byte_size):
        self.type_ref = type_ref
        self.byte_size = byte_size

    def __repr__(self):
        return "<Pointer @ %s>" % self.__str__()

    def __str__(self):
        return "%s*" % self.type_ref


class ArrayType:

    def __init__(self, type_ref, size):
        self.type_ref = type_ref
        self.size = size

    @property
    def byte_size(self):
        return self.type_ref.byte_size * self.size

    def __repr__(self):
        return "<ArrayType @ %s>" % self.__str__()

    def __str__(self):
        return "%s[%s]" % (self.type_ref, self.size)


class EnumsType:

    def __init__(self, name, byte_size, type_ref,
                 decl_file, decl_line):
        self.name = name
        self.byte_size = byte_size
        self.type_ref = type_ref
        self.decl_file = decl_file
        self.decl_line = decl_line

        self.enumerators = {}

    def add_enumerator(self, name, value):
        self.enumerators[name] = value

    def __repr__(self):
        return "<Enums @ %s>" % self.name

    def __str__(self):
        return "Enums %s" % self.name


class Structure:

    def __init__(self, name, byte_size, decl_file, decl_line):
        self.name = name
        self.byte_size = byte_size
        self.decl_file = decl_file
        self.decl_line = decl_line

        self.members = {}

    def add_members(self, offset, member):
        self.members[offset] = member

    def __repr__(self):
        return "<Structure @ %s %s>" % (self.name, self.byte_size)

    def __str__(self):
        return "struct %s" % self.name


class Member:

    def __init__(self, name, type_ref, decl_file, decl_line):
        self.name = name
        self.type_ref = type_ref
        self.decl_file = decl_file
        self.decl_line = decl_line

    def __repr__(self):
        return "<Member @ name: %s type: %s>" % (
            self.name, self.type_ref)

    def __str__(self):
        return "%s" % self.name


class Subroutine:

    def __init__(self, prototyped):
        self.prototyped = prototyped

    def __repr__(self):
        return "<Subroutine @ %s>" % self.prototyped

    def __str__(self):
        return self.__repr__()
