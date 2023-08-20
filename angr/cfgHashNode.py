from HNSW4hashes.node_hash import HashNode


class CFGHashNode(HashNode):

    def __init__(self, id, hashAlgorithm, func_name, binary_name):
        super().__init__(id, hashAlgorithm)
        self.func_name = func_name
        self.binary_name = binary_name
