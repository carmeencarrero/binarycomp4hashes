from basicBlock import BasicBlock


class ControlFlowGraph:

    def __init__(self, project):
        self.cfg = project.analyses.CFGFast()

    def get_bb_function(self, function_name):
        func_node = self.cfg.kb.functions.function(name=function_name)

        if func_node is not None:
            basic_blocks = []
            for block in func_node.blocks:
                block_instructions = block.capstone.insns
                if block_instructions:
                    basic_block = BasicBlock(block.addr, block_instructions, block.bytes)
                    basic_blocks.append(basic_block)

        return basic_blocks

