

class DwarfInfoParser:

    def __init__(self, dwarf_info):
        self.dwarf_info = dwarf_info


if __name__ == "__main__":

    import angr

    proj = angr.Project("./cp", load_options={"load_debug_info": True})
    info_parser = DwarfInfoParser(proj.loader.main_object.dwarf)
