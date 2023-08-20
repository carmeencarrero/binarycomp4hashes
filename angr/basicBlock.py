class BasicBlock:

    def __init__(self, addr, instructions, _bytes):
        self.addr = addr
        self.instructions = instructions
        self.bytes = _bytes
