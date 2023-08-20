import argparse
from evaluation import *


def main():
    parser = argparse.ArgumentParser(description="Identify functions within a binary tool")
    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")

    add_parser = subparsers.add_parser("add", help="Add hash of the functions to the database")
    add_parser.add_argument("--database", required=True, help="Database name")
    add_parser.add_argument("--f", dest="file", required=True, help="File name")

    search_parser = subparsers.add_parser("search", help="Compare the database hash with the file")
    search_parser.add_argument("--database", required=True, help="Database name")
    search_parser.add_argument("--f", dest="file", required=True, help="File name")
    search_parser.add_argument("--percentage", type=float, required=True, help="Search percentage")

    args = parser.parse_args()

    if args.subcommand == "add":
        add_to_database(args.database, args.file)
    elif args.subcommand == "search":
        search_database(args.database, args.file, args.percentage)
    else:
        print("Invalid subcommand. Use --help for usage information.")


if __name__ == '__main__':
    main()
