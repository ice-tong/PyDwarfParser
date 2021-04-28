from elftools.dwarf.descriptions import describe_attr_value
from elftools.dwarf.dwarf_expr import DWARFExprParser

from parse_dwarf_types import DwarfTypesParser
from dwarf_compile_unit import CompileUnit
from dwarf_function import Function
from dwarf_variable import Variable


class DwarfInfoParser:

    def __init__(self, dwarf_info):
        self.dwarf_info = dwarf_info

        self._cu_by_cuoffset = {}
        self._func_by_offset = {}
        self._variable_by_offset = {}
        self._stmt_address_to_program_line = {}

        self.types_parser = DwarfTypesParser(self.dwarf_info)

        # parse
        for cu in self.dwarf_info.iter_CUs():
            self._expr_parser = DWARFExprParser(cu.structs)
            for die in cu.iter_DIEs():
                self._parse(die)
            self._parse_program_line(cu)

    def _parse_program_line(self, cu):
        # lineprogram = cu.dwarfinfo.line_program_for_CU(cu)
        # lineprogram_entries = lineprogram.get_entries()

        # TODO: parse program line
        ...

    def _parse(self, die):

        if die.tag == "DW_TAG_compile_unit":
            self._parse_compile_unit(die)

        elif die.tag == "DW_TAG_subprogram":
            self._parse_subprogram(die)

        elif die.tag == "DW_TAG_variable":
            self._parse_variable(die)
        elif die.tag == "DW_TAG_formal_parameter":
            self._parse_variable(die)

        if die.tag == "DW_TAG_compile_unit":
            return

        # if has children, iter them, except DW_TAG_compile_unit.
        for child_die in die.iter_children():
            self._parse(child_die)

    def _parse_compile_unit(self, die):
        name_attribute = die.attributes.get("DW_AT_name")
        name = None if name_attribute is None else \
            name_attribute.value.decode("utf-8", errors="ignore")

        comp_dir_attribute = die.attributes.get("DW_AT_comp_dir")
        comp_dir = None if comp_dir_attribute is None else \
            comp_dir_attribute.value.decode("utf-8", errors="ignore")

        producer_attribute = die.attributes.get("DW_AT_producer")
        producer = None if producer_attribute is None else \
            producer_attribute.value.decode("utf-8", errors="ignore")

        lang_attribute = die.attributes.get("DW_AT_language")
        lang = None if lang_attribute is None else describe_attr_value(
            lang_attribute, die, self.dwarf_info.debug_info_sec.global_offset)

        low_pc_attribute = die.attributes.get("DW_AT_low_pc")
        low_pc = None if low_pc_attribute is None else \
            low_pc_attribute.value

        high_pc_attribute = die.attributes.get("DW_AT_high_pc")
        high_pc = None if high_pc_attribute is None else \
            high_pc_attribute.value

        compile_unit = CompileUnit(
            name, comp_dir, lang, producer, low_pc, high_pc)
        setattr(compile_unit, "die", die)
        self._cu_by_cuoffset[die.cu.cu_offset] = compile_unit

    def _parse_subprogram(self, die):
        # a lazy way, get general attr by types_parser's method.
        name, _, decl_file, decl_line, _ = self.types_parser._get_general_attribute(die)  # noqa: E501

        low_pc_attribute = die.attributes.get("DW_AT_low_pc")
        low_pc = None if low_pc_attribute is None else \
            low_pc_attribute.value

        high_pc_attribute = die.attributes.get("DW_AT_high_pc")
        high_pc = None if high_pc_attribute is None else \
            high_pc_attribute.value

        # TODO: DW_AT_frame_base, DW_AT_prototyped, DW_AT_GNU_*_call_sites
        func = Function(name, low_pc, high_pc, decl_file, decl_line)
        setattr(func, "die", die)
        self._func_by_offset[die.offset] = func

    def _parse_variable(self, die):
        # a lazy way, get general attr by types_parser's method.
        name, _, decl_file, decl_line, type_ref_offset \
            = self.types_parser._get_general_attribute(die)
        type_ref = self.types_parser.get_type_by_offset(type_ref_offset)

        location_attribute = die.attributes.get("DW_AT_location")
        location = None if location_attribute is None else \
            self._expr_parser.parse_expr(location_attribute.value)

        variable = Variable(
            name, type_ref, decl_file, decl_line,
            True if die.tag == "DW_TAG_formal_parameter" else False,
            location)
        setattr(variable, "die", die)
        self._variable_by_offset[die.offset] = variable


if __name__ == "__main__":

    import angr

    proj = angr.Project("./cp", load_options={"load_debug_info": True})
    info_parser = DwarfInfoParser(proj.loader.main_object.dwarf)

    for variable in info_parser._variable_by_offset.values():
        print(variable)
