#!/usr/bin/env python

# print("\n" + "*"*30 + "\n")
import construct as C
import networkx as nx
import matplotlib.pyplot as plt
import re
import flare_emu
from typing import Type, Callable
import struct as st
from triton import *
from enum import Enum
from lief import PE
import io
from hexdump import hexdump
from functools import partial, reduce
# from capstone import *

class ControlFlowNode:
    pass

class TypeAncestor(Enum):
    NONE = 0
    OPCODE = 1
    JMP = 2

def count(iterable):
    return reduce(lambda x, y: x + 1, iterable, 0)

class ControlFlowNode:

    def __init__(self, addr: int, opcode: bytes, str_opcode: str):
        self._addr: int = addr
        self.new_addr = 0
        self._opcode: bytes = opcode
        self._str_opcode: str = str_opcode
        self._f_modify: Callable[[ControlFlowNode], None] = None


    @property
    def addr(self):
        return self._addr


    @property
    def op_len(self):
        return len(self._opcode)


    @property
    def opcode(self):
        return self._opcode


    @property
    def str_opcode(self):
        return self._str_opcode


    def process_triton(self, triton):
        ins = Instruction()
        ins.setOpcode(self.opcode)
        ins.setAddress(self.addr)
        triton.processing(ins)
        return ins


    def __eq__(self, other):
        if other is None:
            return False
        return self.opcode == other.opcode and self.addr == other.addr


    def __str__(self):
        return f"0x{self.addr:08x} {self.opcode.hex():<16} {self.str_opcode}"


    def __repr__(self):
        return f"ControlFlowNode({self.addr=:08x}, {self.str_opcode=})"


    def __hash__(self):
        return hash((self.addr, self.opcode))


class AddressExistsAndNotEqualError(Exception): pass
class ToMuchAncestorsError(Exception): pass

class ControlFlow:
    pass

class ControlFlow:
    def __init__(self):
        self.lastAdded: ControlFlowNode = None
        self.graph = nx.DiGraph()


    def __getitem__(self, key: ControlFlowNode) -> ControlFlowNode :
        return self.graph[key]

    def predecessors(self, opcode):
        return self.graph.predecessors(opcode)

    def push_inst(self, value: ControlFlowNode):
        if self.graph.has_node(value):
            self.graph.nodes[value]['visited'] += 1
        else:
            self.graph.add_node(value, visited=1)
        lst_val = self.lastAdded
        if lst_val is None:
            self.lastAdded = value
            return
        if len(lst_val.opcode) + lst_val.addr == value.addr:
            chosenType = TypeAncestor.OPCODE
        else:
            chosenType = TypeAncestor.JMP
        self.graph.add_edge(lst_val, value, type=chosenType)
        self.lastAdded = value
        return self.graph.nodes[value]['visited'] == 1


    def __iter__(self):
        for node in self.graph:
            yield node, self[node]


    def remove_empty_nodes(self):
        for node, edges in self:
            if count(G.predecessors(node)) == 0 and self.root not in edges:
                self.graph.remove_node(node)


    def follow_the_controlflow(self):
        visited_keys = set()
        start = next((n for n, d in self.graph.in_degree() if d == 0), None)
        if start is None:
            raise Exception("root not found")
        lst = None
        def get_next_children(node):
            res = sorted(self.graph[node].items(), key=lambda x: x[1]['type'].value, reverse=False)
            return iter(i[0] for i in res)
        visited = set()

        visited.add(start)
        stack = [iter([start])] + [get_next_children(start)]
        while stack:
            children = stack[-1]
            try:
                child = next(children)
                if child not in visited:
                    yield child
                    visited.add(child)
                    stack.append(get_next_children(child))
            except StopIteration:
                stack.pop()

    def __str__(self):
        res = []
        lst = None
        for f in self.follow_the_controlflow():
            res.append(f"{self.graph.nodes[f]['visited']:>4} {f}")
        return "\n".join(res)


    def __len__(self):
        return len(self.graph)


    def remove_node_from_flow(self, node: ControlFlowNode):
        """
        For now it's allowed to delete only the node that has only one ancestor
        """
        if len(self.graph[node]) != 1:
            print(f"{[str(i) for i in self.graph[node]]}")
            raise Exception(f"Has more than one successor {node}")
        if node.addr == 0x1400242c2:
            print("LOL", node)
        next_node = next(iter(self.graph[node].items()))
        parents = self.graph.predecessors(node)
        for parent in parents:
            self.graph.add_edge(parent, next_node[0], **next_node[1])
        self.graph.remove_node(node)

    def replace_node_in_a_flow(self, old_node: ControlFlowNode, new_node: ControlFlowNode):
        successors = self.graph[old_node]
        predecessors = self.graph.predecessors(old_node)
        self.graph.add_node(new_node)
        for successor, attrs in successors.items():
            self.graph.add_edge(new_node, successor, **attrs)
        for predecessor in predecessors:
            self.graph.add_edge(predecessor, new_node, **self.graph.edges[predecessor, old_node])
        self.graph.remove_node(old_node)


    def total_code_length(self):
        return sum(len(i.opcode) for i in self)


    def export_to_png(self, filename="index.html"):
        nx.draw(self.graph, with_labels=True)
        plt.savefig('test.png')


    def save_to_exe(self, filename):
        code = io.BytesIO()
        cur_offset = 0
        used_insts = {}
        re_addr = re.compile(r"^j\w{1,3}\s+0x[0-9a-f]+$")
        re_jne = re.compile(r"^jn?e\s+0x[0-9a-f]+$")
        lst_node = None
        for node in self.follow_the_controlflow():
            used_insts[node] = code.tell()
            code.write(node.opcode)
            # if (cur_suc := next(iter(self.graph[node], None))) in used_insts:
            #     offset = used_insts[cur_suc]
            #     new_node
            #     used_insts[new_node] =
            #     code.write(b'\xe9' + '')
        code.write(b"\xc9\xc3") # leave; ret;

        for node, cur_offset in used_insts.items():
            jmp_node = next((n for n, attrs in self[node].items() if attrs['type'] == TypeAncestor.JMP), None)
            if jmp_node is None:
                continue
            if re_addr.match(node.str_opcode):
               # not re_jne.match(node.str_opcode):
                print(f"Change node type: {node}")
                try:
                    suc_offset = used_insts[jmp_node]
                except Exception as e:
                    continue
                delta = suc_offset - cur_offset - len(node.opcode)
                s, jmp_offset = detect_jmp_size(node)
                new_offset = st.pack(s, delta)
                code.seek(cur_offset + jmp_offset)
                code.write(new_offset)
                code.seek(0, io.SEEK_END)

        code.flush()
        pe = PE.Binary("binary.exe", PE.PE_TYPE.PE32_PLUS)
        section_text                 = PE.Section(".text")
        section_text.content         = code.getbuffer()
        section_text.virtual_address = 0x24000
        section_text.characteristics = PE.SECTION_CHARACTERISTICS.CNT_CODE | PE.SECTION_CHARACTERISTICS.MEM_READ | PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        section_data                 = PE.Section(".data")
        section_data.content         = [0]*100
        section_data.virtual_address = 0x35000
        pe.add_section(section_text, PE.SECTION_TYPES.TEXT)
        pe.add_section(section_data, PE.SECTION_TYPES.DATA)
        # pe.optional_header.imagebase = 0x140000000
        pe.optional_header.addressof_entrypoint = section_text.virtual_address
        # pe.optional_header.baseof_code = 0x24000
        # pe.optional_header.addressof_entrypoint = 0x24000
        builder = PE.Builder(pe)
        builder.build()
        builder.write(filename)


trace = ControlFlow()

def detect_jmp_size(opcode: ControlFlowNode):
    st_nums = {
        1: "b",
        2: "h",
        4: "i",
        8: "q"
    }
    res = st_nums.get(len(opcode.opcode) - 1, None)
    if res is None:
        res = st_nums.get(len(opcode.opcode) - 2, None)
        print(opcode.opcode, opcode.str_opcode)
        return res, 2
    return res, 1

def remove_single_jmps():
    rltv_jmps = [
        b"\xeb", # relative jmps
        b"\xe9"]
    abs_jmp = b"\xea" # absolute jmp with addr in operand
    allowed_jmps = rltv_jmps + [abs_jmp] # allowed jmp int for removal

    global trace

    def is_ancestor_alone(opcode: ControlFlowNode):
        # for jmp to remove there is always only one ancestor
        successor = next(iter(trace[opcode]))
        res = count(trace.graph.predecessors(successor)) == 1
        return res


    def has_parents(opcode: ControlFlowNode):
        res = count(trace.predecessors(opcode)) > 0
        return res


    for opcode, nxt_opcode in list(trace):
        if any(opcode.opcode.startswith(i) for i in allowed_jmps) \
            and is_ancestor_alone(opcode) \
            and has_parents(opcode):
            trace.remove_node_from_flow(opcode)


def symbolization_init(triton):
    triton.symbolizeRegister(triton.registers.eax)
    triton.symbolizeRegister(triton.registers.ebx)
    triton.symbolizeRegister(triton.registers.ecx)
    triton.symbolizeRegister(triton.registers.edx)


def reverse_symbolic_trace(opcode, count=5):
    global trace
    global tracked_opcodes

    def iter_parents(opcode=opcode, count=count):
        get_nxt_parent = lambda node: min(trace.graph.predecessors(node),
                                          key=lambda x: abs(node.addr - x.addr))
        cur = count
        parent = opcode
        while cur > 0:
            parent = get_nxt_parent(parent)
            yield parent
            cur -= 1

    trace_to_symbolic = [parent for parent in iter_parents()][::-1] + [opcode]

    triton = TritonContext()
    triton.setArchitecture(ARCH.X86_64)
    symbolization_init(triton)
    ctx = triton.getAstContext()
    lst_ins = None
    for opcode in trace_to_symbolic:
        lst_ins = opcode.process_triton(triton)
    op_ast = triton.getPathPredicate()
    model = triton.getModel(ctx.lnot(op_ast))

    # for expr in lst_ins.getSymbolicExpressions():
    #     print('\t', expr)

    def change_opcode(node: ControlFlowNode):
        def create_rule(tracked_opcode):
            opcode_change = partial(re.sub, b"^" + tracked_opcode[0], b"\xeb")
            str_change    = partial(re.sub, tracked_opcode[1], "jmp")
            return (tracked_opcode[0], opcode_change, str_change)
        for t, opcode_change, str_change in map(create_rule, tracked_opcodes):
            if node.opcode.startswith(t):
                new_opcode = opcode_change(node.opcode)
                new_str_opcode = str_change(node.str_opcode)
                new_addr = node.addr
                # new_opcode = node.opcode.replace(from_, to_)
                new_node = ControlFlowNode(new_addr, new_opcode, new_str_opcode)
                trace.replace_node_in_a_flow(node, new_node)

    if not model:
        if lst_ins.isConditionTaken():
            trace.graph.nodes[opcode]['f_modify'] = change_opcode
            # opaque predicate: always taken
        else:
            trace.graph.nodes[opcode]['f_modify'] = trace.remove_node_from_flow
            # opaque predicate: never taken
    else:
        print("NPred", model, opcode)



tracked_opcodes = [
    (b"\x70", "jo"),
    (b"\x71", "jno"),
    (b"\x72", "jb"),
    (b"\x73", "jnb"),
    # (b"\x74", "jz"),
    # (b"\x75", "jnz"),
    (b"\x76", "jbe"),
    (b"\x77", "ja"),
    (b"\x79", "jns"),
    (b"\x7d", "jge"),
    (b"\x7e", "jle"),
] # "jo", "jno", "jb", "jbe", "jle"


was_here = False

def int_hook(uc, cur_addr, op_size, flemu):
    global trace
    global sym_tested
    global tracked_opcodes
    global was_here
    eh = flemu["EmuHelper"]
    cond_jmp = [i[0] for i in tracked_opcodes]
    opcode: bytes = bytes(eh.getEmuBytes(cur_addr, op_size))
    str_op = eh.analysisHelper.getDisasmLine(cur_addr)

    alter_trace = ControlFlow()
    def alternate_path(uc, cur_addr, op_size, flemu):
        pass

    skip_ints = [
        0x140025f3c, # The address of skip insn
    ]
    if cur_addr in skip_ints:
        eh.uc.reg_write(eh.regs['ip'], cur_addr + op_size)

    if cur_addr == 0x1400250c7:
        key_st = C.Struct(
            "key" / C.Array(4, C.Int32ul),
        )
        key = key_st.parse(eh.getEmuBytes(0x140025f66, 0x10))
        print("Key:", ", ".join(map(hex, key.key)))

    cur_node = ControlFlowNode(cur_addr, opcode, str_op)
    is_new = trace.push_inst(cur_node)

    if is_new and any(opcode.startswith(i) for i in cond_jmp):
        reverse_symbolic_trace(cur_node)


def process_funcs():
    global trace
    nodes = list(trace.graph.nodes)
    for node in nodes:
        if trace.graph.nodes[node].get('f_modify', None) is not None:
            trace.graph.nodes[node]['f_modify'](node)

regs = [ "rax", "rbx", "rcx", "rdx",
         "rsi", "rdi",  "r8",  "r9",
         "r10", "r11", "r12", "r13",
         "r14", "r15", "rip", "rbp",
         "rsp",
        ]

reg_state = {}
stack_state = {}

def collect_trace(stage):
    global regs
    global reg_state
    filename, address = stage
    eh = flare_emu.EmuHelper(samplePath=filename)
    for reg in regs:
        eh.uc.reg_write(eh.regs[reg], reg_state.get(reg, 0))
        reg_state[reg] = eh.getRegVal(reg)

    params = dict(instructionHook=int_hook, count=50000, strict=False, skipCalls=True)
    if stack_state:
        start, end, permissions = stack_state['params']
        eh.uc.mem_write(start, bytes(stack_state['mem']))
        params["registers"] = reg_state

    eh.emulateFrom(address, **params)
    regions = [i for i in eh.uc.mem_regions()]

    for reg in regs:
        print(f"{reg:<3} 0x{eh.getRegVal(reg):016x}")
        reg_state[reg] = eh.getRegVal(reg)
    for start, end, permissions in regions:
        if start <= reg_state['rsp'] <= end:
            stack_state['mem'] = eh.uc.mem_read(start, end-start)
            stack_state['params'] = (start, end, permissions)
    # test_addr = 0x00000001400245E9
    # buf = eh.getEmuBytes(test_addr, 100*8)
    # with open("some_bytes_emu.bin", 'wb') as f:
    #     f.write(buf)


def check_trace():
    for node, edge in trace:
        if (parents_cnt := count(trace.graph.predecessors(node))) > 1:
            print(f"{parents_cnt}: {node}")
        # if (ances_cnt := len(node.ancestors)) > 1:
        #     print(f"{ances_cnt}: {node}")
    print()


def main():
    stages = [
        # Filename               virtual address     target_file
        ("sakura-agent.exe.bin", 0x0000000140024168, "deob_0.bin"),
    ]

    global trace
    global reg_state

    for i, stage in enumerate(stages):
        trace = ControlFlow()
        print(f"Stage {i+1}")
        collect_trace(stage[:2])

        process_funcs()
        remove_single_jmps()
        with open(f"{stage[2]}.txt", 'w') as f:
            f.write(str(trace))


        trace.save_to_exe(stage[2])


if __name__ == '__main__':
    main()
