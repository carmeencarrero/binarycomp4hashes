import tlsh


class Function:

    def __init__(self, name, basicblocks):
        self.name = name
        self.bb = basicblocks

    def get_name(self):
        return self.name

    def get_basic_blocks(self):
        return self.bb

    def calculate_hash(self):
        basic_blocks = self.bb

        if len(basic_blocks) > 1:
            func_bytes = b"".join(block.bytes for block in basic_blocks)
        else:
            basic_block = basic_blocks[0]
            func_bytes = basic_block.bytes

        func_hash = tlsh.hash(func_bytes)
        return func_hash

