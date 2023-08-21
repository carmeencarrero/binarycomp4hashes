import logging
import angr
import os
import sys

from binary import Binary
from cfgHashNode import CFGHashNode
from HNSW4hashes.hnsw import HNSW
from HNSW4hashes.tlsh_algorithm import TLSHHashAlgorithm


def run_angr(binary_file):
    project = angr.Project(binary_file, auto_load_libs=False)
    return Binary(project)


def analyse_program(binary_file):
    logging.info('Print metadata')
    binary = run_angr(binary_file)
    sys.setrecursionlimit(2500)
    binary.print_metadata()
    return binary.obtain_hashes()


def add_to_database(database, file):
    function_hashes_binary = analyse_program(file)
    if not os.path.exists(database):
        myHNSW = HNSW(M=4, ef=4, Mmax=8, Mmax0=16)
        myHNSW.dump(database)

    myHNSW = HNSW.load(database)
    counter = 0
    for func_name, hash_value in function_hashes_binary.items():
        node = CFGHashNode(hash_value, TLSHHashAlgorithm, func_name, file)
        myHNSW.add_node(node)
        counter = 0 + 1

    myHNSW.dump(database)
    print(f'Number of functions added to database {database}: {counter}')
    print(f'Adding to database {database} from file {file}')


def print_matched_functions(matched_functions, binary, value):
    archivo = f"matched_functions_knn_{binary}.txt"
    if value == 1:
        archivo = f"matched_functions_percentage_{binary}.txt"

    if matched_functions:
        with open(archivo, "w") as archivo:
            archivo.write("Matched Functions:\n")
            for func_name_binary, binary, func_name_database, binary_database in matched_functions:
                archivo.write(f'The function {func_name_binary} in the binary {binary} has matched '
                              f'with the function {func_name_database} in the database (binary:{binary_database})\n')
                archivo.write("-" * 30 + "\n")
    else:
        archivo.write("No matched functions found.")


def search_database(database, file, percentage):
    if not os.path.exists(database):
        logging.error('No database found')
        return 1

    function_hashes_binary = analyse_program(file)
    myHNSW = HNSW.load(database)
    matched_functions = []
    matched_functions_knn = []
    counter = 0

    print(f'Searching database {database} with file {file} and percentage {percentage}')
    for func_name, hash_binary in function_hashes_binary.items():
        query_node = CFGHashNode(hash_binary, TLSHHashAlgorithm, func_name, file)
        counter = counter + 1
        results_percentage = myHNSW.percentage_search(query_node, percentage=percentage)
        results_knn = myHNSW.knn_search(query_node, k=5, ef=1)

        for result in results_percentage:
            matched_functions.append((func_name, file, result.func_name, result.binary_name))
        for result in results_knn:
            matched_functions_knn.append((func_name, file, result.func_name, result.binary_name))

    print_matched_functions(matched_functions, file, 1)
    print_matched_functions(matched_functions_knn, file, 2)
    print(f'Number of functions in the binary {file}: {counter}')
    print('The result of the searching is in matched_functions_percentage/knn_namebinary.txt files')
