#!/usr/bin/env python
import os
from z3 import *
from functools import reduce
from string import ascii_lowercase
from itertools import product


def Little(a):
    return Or(
        And(a >= ord("a"), a <= ord("z")),
    )

def Check(length, hash_val):
    # form str
    my_str = [BitVec(f"c_{i}", 32) for i in range(length)]
    s = Solver()
    i = length-1
    s.add([Little(my_str[j]) for j in range(0, i-3)])
    s.add(my_str[i-3] == ord("."))
    s.add(my_str[i-2] == ord("e"))
    s.add(my_str[i-1] == ord("x"))
    s.add(my_str[i-0] == ord("e"))


    v4 = BitVecVal(0, 32)
    filename_of_a_parent = my_str
    for v5 in filename_of_a_parent:
        v4 = v5 + 17 * v4
    s.add(
        v4 == BitVecVal(hash_val, 32)
    )

    while s.check() == sat:
        mod = s.model()
        yield mod, my_str
        s.add(Or([mod[i] != i for i in my_str]))
    return None, my_str


def smt(value, length):
    res = False
    for m, my_str in Check(length, value):
        word = reduce(lambda x, y: x + chr(y), [""] + [m[i].as_long() for i in my_str])
        print(f"    {word}")
        res = True
    return res


def get_hash(fn):
    res = 0
    for i in fn:
        res = (res*17 + i) & 0xffffffff
    return res


def brute_force(value, length):
    alph = ascii_lowercase
    check_length = length - 4
    a = product(alph, repeat=check_length)

    res = False
    for test_str_t in a:
        test_str = "".join(test_str_t) + ".exe"
        if get_hash(test_str.encode()) == value:
            print(f"    {test_str}")
            res = True
    return res


def main():
    values = [
        0xab341dfa, # winword.exe
        0x190bc0f1,
        0x639ebcbf,
        0xa6afb610,
        0x4d16ce36,
        0x64820461,
        0x84F39C89,
    ]
    for value in values:
        print(f"Search for 0x{value:08x}:")
        for length in [7, 8, 9, 10, 11]:
            print(f" Length {length}")
            if length < 10:
                print("  Brute forcing")
                brute_force(value, length)
            print("  SMT solving")
            res = smt(value, length)
            if res:
                break

def time_testing():
    """
    Before tests comment print in target functions
    """
    import timeit
    for i in [5, 6, 7, 8, 9, 10, 11]:
        print(f"Brute length: {i-4}:")
        if i < 9:
            number = 100
        elif 9 <= i < 10:
            number = 10
        else:
            number = 1
        print("  SMT All sols Time: ", timeit.timeit(f"smt(0xab341dfa, {i})", globals=globals(), number=number)/number)
        print("  BruteForce Time: ", timeit.timeit(f"brute_force(0xab341dfa, {i})", globals=globals(), number=100)/100)

    # Find()
    # brute_force()
    # check_this()


def find_hashes():
    """
    For filename collection
    """
    alph = ascii_lowercase
    filenames = [alph[:i] + ".exe" for i in range(1, 8)]
    for i in filenames:
        print(hex(get_hash(i.encode())))


def get_possible_filenames():
    # You can geather your own dictionary
    ls = []
    with open("./listexe.txt") as f:
        ls = [os.path.basename(f).strip() for f in f.readlines()]

    return set(ls)


if __name__ == '__main__':
    main()
    # find_hashes()
