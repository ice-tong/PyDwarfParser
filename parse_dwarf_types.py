from elftools.dwarf.descriptions import (
    _ATTR_DESCRIPTION_MAP, _EXTRA_INFO_DESCRIPTION_MAP)
from dwarf_types import (
    BaseType, ConstType, TypeDef, PointerType, ArrayType,
    EnumsType, Structure, Member, Subroutine)


class DwarfTypesParser:
    """
    Basicly usage:
    >>> types_parser = DwarfTypesParser(proj.loader.main_object.dwarf)
    >>> ty_ref_offset = die.attributes.get("DW_AT_type").value + die.cu.cu_offset  # noqa: E501
    >>> types_parser.get_type_by_offset(ty_ref_offset)

    Friendly notes:
        cu stands Compile Unit
        die stands Debug Information Entry
        offset stands die.offset
        cuoffset stands die.cu.cu_offset
        type_ref stands type reference

        each type class has attached `die` attribute.

    Implemented Types:
        BaesType, ConstType, TypeDef, PointerType, ArrayType, EnumsType
        Structure, Subroutine.

    Known but NotImplemented Types:
        VolatileType

    UnKnown Types:
        ...
    """

    def __init__(self, dwarf_info):

        self.dwarf_info = dwarf_info

        self.section_offset = dwarf_info.debug_info_sec.global_offset

        # Maybe we can integrate these types into one stuff...
        self._base_type_by_offset = {}
        self._const_type_by_offset = {}
        self._typedef_by_offset = {}
        self._pointer_type_by_offset = {}
        self._array_type_by_offset = {}
        self._enums_type_by_offset = {}
        self._structure_by_offset = {}
        self._subroutine_type_by_offset = {}

        # parse types
        for cu in dwarf_info.iter_CUs():
            for die in cu.iter_DIEs():
                self._parse_types(die)

        # replace type reference offset
        for type_ in self._iter_types():
            if hasattr(type_, "type_ref"):
                type_ref_offset = getattr(type_, "type_ref")
                try:
                    type_ref = self.get_type_by_offset(type_ref_offset)
                    setattr(type_, "type_ref", type_ref)
                except KeyError as e:
                    print(e)
                    continue

    #
    # parse method
    #

    def _parse_types(self, die):
        """
        parse types, subprogram and compile unit.
        """

        if die.tag == "DW_TAG_base_type":
            self._parse_base_type(die)

        elif die.tag == "DW_TAG_const_type":
            self._parse_const_type(die)

        elif die.tag == "DW_TAG_typedef":
            self._parse_typedef(die)

        elif die.tag == "DW_TAG_pointer_type":
            self._parse_pointer_type(die)

        elif die.tag == "DW_TAG_array_type":
            self._parse_array_type(die)

        elif die.tag == "DW_TAG_enumeration_type":
            self._parse_enums_type(die)

        # union and class are not implemented yet, use structure.
        elif die.tag == "DW_TAG_structure_type":
            self._parse_structure_type(die)
        elif die.tag == "DW_TAG_union_type":
            self._parse_structure_type(die)
        elif die.tag == "DW_TAG_class_type":
            self._parse_structure_type(die)

        elif die.tag == "DW_TAG_subroutine_type":
            self._parse_subroutine_type(die)

        else:
            ...

        # if has children, iter them.
        for child_die in die.iter_children():
            self._parse_types(child_die)

    def _get_value_by_attribute(self, die, attribute):
        """
        A foolish method to extract expected value from attribute...
        Need improve!
        """
        # in the case of str form data `DW_FORM_strp`, return str
        if attribute.form == "DW_FORM_strp":
            return attribute.value.decode("utf-8", errors="ignore")

        # parse `DW_AT_decl_file`
        if attribute.name == "DW_AT_decl_file":
            if attribute.value == 0:
                return attribute.value
            lineprogram = die.dwarfinfo.line_program_for_CU(die.cu)
            file_entry = lineprogram.header.file_entry[attribute.value-1]
            file_name = file_entry.name.decode("utf-8", errors="ignore")
            file_dir_bytes = lineprogram.header.include_directory[file_entry.dir_index-1]  # noqa: E501
            file_dir = file_dir_bytes.decode("utf-8", errors="ignore")
            return file_dir + "/" + file_name

        # if extra_info is not empty, return extra_info
        extra_info_func = _EXTRA_INFO_DESCRIPTION_MAP[attribute.name]
        extra_info = extra_info_func(attribute, die, self.section_offset)
        if extra_info:
            return extra_info

        # the last choice
        descr_func = _ATTR_DESCRIPTION_MAP[attribute.form]
        val_description = descr_func(attribute, die, self.section_offset)
        if val_description:
            return val_description

        return attribute.value

    def _get_general_attribute(self, die):
        """
        Get attribute include:
            name, byte_size, decl_file, decl_line and type_ref_offset.
        Return None if not exist.
        """
        name_attribute = die.attributes.get("DW_AT_name")
        name = None if name_attribute is None else \
            self._get_value_by_attribute(die, name_attribute)

        size_attribute = die.attributes.get("DW_AT_byte_size")
        byte_size = None if size_attribute is None else \
            self._get_value_by_attribute(die, size_attribute)

        decl_file_attribute = die.attributes.get("DW_AT_decl_file")
        decl_file = None if decl_file_attribute is None else \
            self._get_value_by_attribute(die, decl_file_attribute)

        decl_line_attribute = die.attributes.get("DW_AT_decl_line")
        decl_line = None if decl_line_attribute is None else \
            self._get_value_by_attribute(die, decl_line_attribute)

        type_ref_attribute = die.attributes.get("DW_AT_type")
        type_ref_offset = None if type_ref_attribute is None else \
            type_ref_attribute.raw_value + die.cu.cu_offset

        return name, byte_size, decl_file, decl_line, type_ref_offset

    def _parse_base_type(self, die):
        name, byte_size, *_ = self._get_general_attribute(die)

        encoding_attribute = die.attributes.get("DW_AT_encoding")
        encoding = self._get_value_by_attribute(die, encoding_attribute)

        base_type = BaseType(name, byte_size, encoding)
        setattr(base_type, "die", die)
        self._base_type_by_offset[die.offset] = base_type

    def _parse_const_type(self, die):
        *_, type_ref_offset = self._get_general_attribute(die)
        const_type = ConstType(type_ref_offset)
        setattr(const_type, "die", die)
        self._const_type_by_offset[die.offset] = const_type

    def _parse_typedef(self, die):
        name, _, decl_file, decl_line, type_ref_offset \
            = self._get_general_attribute(die)
        typedef = TypeDef(name, type_ref_offset, decl_file, decl_line)
        setattr(typedef, "die", die)
        self._typedef_by_offset[die.offset] = typedef

    def _parse_pointer_type(self, die):
        _, byte_size, _, _, type_ref_offset = self._get_general_attribute(die)

        pointer_type = PointerType(type_ref_offset, byte_size)
        setattr(pointer_type, "die", die)
        self._pointer_type_by_offset[die.offset] = pointer_type

    def _parse_array_type(self, die):
        *_, type_ref_offset = self._get_general_attribute(die)
        for child_die in die.iter_children():
            size_attribute = child_die.attributes.get("DW_AT_upper_bound")
            size = 0 if size_attribute is None else size_attribute.value
        array_type = ArrayType(type_ref_offset, size)
        setattr(array_type, "die", die)
        self._array_type_by_offset[die.offset] = die.offset

    def _parse_enums_type(self, die):
        name, byte_size, decl_file, decl_line, type_ref_offset \
            = self._get_general_attribute(die)

        enums = EnumsType(name, byte_size, type_ref_offset,
                          decl_file, decl_line)
        setattr(enums, "die", die)

        for child_die in die.iter_children():
            # pylint: disable=line-too-long
            child_name_attribute = child_die.attributes.get("DW_AT_name")
            child_name = child_name_attribute.value.decode("utf-8", errors="ignore")  # noqa: E501
            const_value = child_die.attributes.get("DW_AT_const_value").value
            enums.add_enumerator(child_name, const_value)

        self._enums_type_by_offset[die.offset] = enums

    def _parse_structure_type(self, die):
        name, byte_size, decl_file, decl_line, _ \
            = self._get_general_attribute(die)

        struct = Structure(name, byte_size, decl_file, decl_line)
        setattr(struct, "die", die)

        for child_die in die.iter_children():
            name, _, decl_file, decl_line, type_ref_offset \
                = self._get_general_attribute(child_die)
            member = Member(name, type_ref_offset, decl_file, decl_line)

            member_loc_attribute = child_die.attributes.get(
                "DW_AT_data_member_location")
            member_offset = 0 if member_loc_attribute is None else \
                member_loc_attribute.value

            struct.add_members(member_offset, member)

        self._structure_by_offset[die.offset] = struct

    def _parse_subroutine_type(self, die):
        """
        A quick-and-dirty method for parse subroutine type, need imporve!
        """
        prototyped_attribute = die.attributes.get("DW_AT_prototyped")
        prototyped = "" if prototyped_attribute is None else \
            self._get_value_by_attribute(die, prototyped_attribute)
        subroutine_type = Subroutine(prototyped)
        setattr(subroutine_type, "die", die)
        self._subroutine_type_by_offset[die.offset] = subroutine_type

    #
    # type process method
    #

    def _iter_types(self, iter_struct_member=True):
        for type_ in self._base_type_by_offset.values():
            yield type_
        for type_ in self._const_type_by_offset.values():
            yield type_
        for type_ in self._typedef_by_offset.values():
            yield type_
        for type_ in self._pointer_type_by_offset.values():
            yield type_
        for type_ in self._array_type_by_offset.values():
            yield type_
        for type_ in self._enums_type_by_offset.values():
            yield type_

        for type_ in self._structure_by_offset.values():
            yield type_

            if iter_struct_member:
                for member in type_.members.values():
                    yield member

        for type_ in self._subroutine_type_by_offset.values():
            yield type_

    def get_type_by_offset(self, offset):
        """
        Maybe we can integrate these types into one stuff...
        """
        if offset is None:
            return BaseType("void", 1, "(void)")
        elif offset in self._base_type_by_offset:
            return self._base_type_by_offset[offset]
        elif offset in self._const_type_by_offset:
            return self._const_type_by_offset[offset]
        elif offset in self._pointer_type_by_offset:
            return self._pointer_type_by_offset[offset]
        elif offset in self._array_type_by_offset:
            return self._array_type_by_offset[offset]
        elif offset in self._typedef_by_offset:
            return self._typedef_by_offset[offset]
        elif offset in self._typedef_by_offset:
            return self._typedef_by_offset[offset]
        elif offset in self._enums_type_by_offset:
            return self._enums_type_by_offset[offset]
        elif offset in self._structure_by_offset:
            return self._structure_by_offset[offset]
        elif offset in self._subroutine_type_by_offset:
            return self._subroutine_type_by_offset[offset]
        else:
            raise KeyError("Unknown offset: %s" % offset)

    #
    # public method and property
    #

    ...


if __name__ == "__main__":

    import angr

    proj = angr.Project("./cp", load_options={"load_debug_info": True})
    types_parser = DwarfTypesParser(proj.loader.main_object.dwarf)

    # test
    for struct in types_parser._structure_by_offset.values():
        print(struct)
