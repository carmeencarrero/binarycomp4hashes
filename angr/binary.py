from function import Function
from cfg import ControlFlowGraph


class Binary:

    def __init__(self, project):
        self.project = project
        self.cfg = ControlFlowGraph(self.project)
        self.functions = self.get_functions()

    def get_functions(self):
        functions = []
        function_manager = self.project.kb.functions

        for addr in function_manager:
            name = function_manager[addr].name
            bb = self.cfg.get_bb_function(name)
            if bb:
                function = Function(name, bb)
                functions.append(function)

        return functions

    def print_metadata(self):
        start_addr = self.project.loader.main_object.min_addr
        end_addr = self.project.loader.main_object.max_addr
        print(f'Data of the file: {self.project.filename}')
        print(f'Entry Point: {hex(self.project.entry)}')
        print(f'Architecture: {self.project.arch.name}')
        print(f'Endian: {self.project.arch.memory_endness}')
        print(f'Bits: {self.project.arch.bits}')
        print(f'Address Range: {hex(start_addr)} - {hex(end_addr)}')

    def obtain_hashes(self):
        function_hashes = {}

        for func in self.functions:
            result = func.calculate_hash()
            if result != 'TNULL':
                function_hashes[func.get_name()] = result

        return function_hashes
