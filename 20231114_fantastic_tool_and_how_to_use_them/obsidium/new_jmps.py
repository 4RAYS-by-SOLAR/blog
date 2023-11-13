#!/usr/bin/env python
from typing import Type, Callable
from struct import pack, unpack
from enum import Enum
import lief
from lief import PE
from hexdump import hexdump
import struct as st
import re
import io
import capstone as cp
import networkx as nx
from triton import *


class Insn_groups(Enum):
    JMP = 1
    RET = 3


class TypeSuccessor(Enum):
    NONE = 0
    FLOW = 1
    JMP = 2


class OpaquePredicate(Enum):
    NONE = 0
    TAKEN = 1
    SKIP = 2


class MemMapper():
    pass


class ControlFlowNode:

    def __init__(self, insn: cp.CsInsn):
        self.insn: cp.CsInsn = insn
        self._f_modify: Callable[[ControlFlowNode], None] = None

    @property
    def addr(self):
        return self.insn.address

    @property
    def is_cond_jmp(self):
        return Insn_groups.JMP.value in self.insn.groups and self.insn.eflags

    @property
    def is_jmp(self):
        return Insn_groups.JMP.value in self.insn.groups

    @property
    def op_len(self):
        return len(self.opcode)

    @property
    def opcode(self):
        return bytes(self.insn.bytes)

    @property
    def str_opcode(self):
        return f"{self.insn.mnemonic:<5} {self.insn.op_str}"

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
class NodeDoesNotExistError(Exception): pass
class NodeExistsError(Exception): pass
class NodeHasAllSuccessors(Exception): pass


class ControlFlow:
    pass


class ControlFlow:
    def __init__(self, entrypoint: ControlFlowNode):
        self.entrypoint: ControlFlowNode = entrypoint
        self.graph = nx.DiGraph()
        self.graph.add_node(entrypoint)

    def __getitem__(self, key: ControlFlowNode) -> ControlFlowNode:
        if type(key) is int:
            return next((i for i in self.graph.nodes if i.addr == key), None)
        elif type(key) is ControlFlowNode:
            return self.graph[key]
        else:
            raise TypeError

    def get_successors_with_metadata(self, key):
        return list(self.graph[key].items())

    def __contains__(self, item):
        if type(item) is int:
            return item in (i.addr for i in self.graph.nodes)

    def predecessors(self, opcode):
        return self.graph.predecessors(opcode)

    def create_edge(self, old_value: ControlFlowNode, new_value: ControlFlow, go_type: TypeSuccessor):
        if not self.graph.has_node(old_value):
            raise NodeDoesNotExistError(old_value)
        # if self.graph.has_node(new_value):
        #     raise NodeExistsError(old_value)
        if len(list(self.graph[old_value])) >= 2:
            raise NodeHasAllSuccessors(old_value)
        self.graph.add_node(new_value)
        self.graph.add_edge(old_value, new_value, type=go_type)

    def replace_node_in_a_flow(self, old_node: ControlFlowNode, new_node: ControlFlowNode):
        successors = self.graph[old_node]
        predecessors = self.graph.predecessors(old_node)
        self.graph.add_node(new_node)
        for successor, attrs in successors.items():
            self.graph.add_edge(new_node, successor, **attrs)
        for predecessor in predecessors:
            self.graph.add_edge(predecessor, new_node, **self.graph.edges[predecessor, old_node])
        self.graph.remove_node(old_node)

    def run_through_flow(self, sort_lambda=None):
        stack: list[ControlFlowNode] = [(self.entrypoint,
                                         None,
                                         self.get_successors_with_metadata(self.entrypoint))]
        used_nodes = {self.entrypoint}
        if sort_lambda is None:
            sort_lambda = lambda x:  x[1]['type'].value
        while stack:
            cur_node = stack.pop()

            new_nodes = [(i, attrs, self.get_successors_with_metadata(i))
                         for i, attrs in self.graph[cur_node[0]].items()
                         if i not in used_nodes]
            used_nodes |= {i[0] for i in new_nodes}
            new_nodes = sorted(new_nodes, key=sort_lambda, reverse=True)
            stack += new_nodes
            yield cur_node

    def save_to_txt(self, filename):
        res = "\n".join(f"{node}" for node, _, _ in self.run_through_flow())
        with open(filename, "w") as f:
            f.write(res)

    def process_predicates(self):
        md = cp.Cs(cp.CS_ARCH_X86, cp.CS_MODE_64)
        md.detail = True

        def modify_opcode(buf: bytes):
            if len(buf) == 2:
                return b"\xeb" + buf[1:3]
            elif len(buf) == 6:
                return b"\xe9" + pack("I", unpack("I", buf[2:])[0] + 1)
            else:
                return None

        for cur_node, _, _ in self.run_through_flow():
            if cur_node.is_cond_jmp and len(self.graph[cur_node]) == 1:
                edge = next(iter(self.graph[cur_node].items()), ([], {"type": TypeSuccessor.NONE}))
                byte_insn = b""
                match edge:
                    case ([], {"type": TypeSuccessor.NONE}): raise Exception("Smth went wrong")
                    case ( _, {"type": TypeSuccessor.FLOW}): self.remove_node_from_flow(cur_node)
                    case ( _, {"type": TypeSuccessor.JMP}):
                        old_bytes = cur_node.opcode
                        new_bytes = modify_opcode(old_bytes)
                        if new_bytes is None:
                            raise Exception(f"implement more options {old_bytes.hex()}")
                        new_node = ControlFlowNode(next(md.disasm(new_bytes, cur_node.addr), None))
                        self.replace_node_in_a_flow(cur_node, new_node)
                    case _:
                        raise Exception(f"Dich has happend: {edge}")

    def clean_jmps(self):
        used_ints = set()
        md = cp.Cs(cp.CS_ARCH_X86, cp.CS_MODE_64)
        md.detail = True
        for cur_node, attrs, successors in self.run_through_flow():
            used_ints.add(cur_node)
            if len(successors) == 1 \
               and (succ := successors[0])[1]['type'] == TypeSuccessor.JMP \
               and succ[0] not in used_ints:
                self.graph.nodes[cur_node]['to_remove'] = True
            elif len(successors) == 1 \
                    and succ[0] in used_ints \
                    and succ[1]['type'] == TypeSuccessor.FLOW:
                self.graph.nodes[cur_node]['add_jmp'] = True

        for node in used_ints:
            match self.graph.nodes[node]:
                case {'to_remove': True}:
                    if node != self.entrypoint:
                        self.remove_node_from_flow(node)
                case {'add_jmp': True}:
                    # -1 -- is a dirty hack to avoid address overlapping
                    data = (b"\xe9\xde\xad\xbe\xef", node.addr + node.op_len - 1)
                    new_node = ControlFlowNode(next(md.disasm(*data), None))
                    self.add_node_to_flow(node, new_node)

    def replace_all_near_jmps(self):
        patterns_nodes = [
            (b"\xeb", b"\xe9\xde\xad\xbe\xef"),
            (b"\x75", b"\x0f\x85\x90\x0d\xca\xfe"),
            (b"\x74", b"\x0f\x84\x90\x0d\xca\xfe"),
        ]

        md = cp.Cs(cp.CS_ARCH_X86, cp.CS_MODE_64)
        md.detail = True
        for cur_node, _, _ in self.run_through_flow():
            for pattern, new_bs in patterns_nodes:
                if cur_node.opcode.startswith(pattern):
                    data = (new_bs, cur_node.addr)
                    new_node = ControlFlowNode(next(md.disasm(*data), None))
                    self.replace_node_in_a_flow(cur_node, new_node)

    def add_node_to_flow(self, node: ControlFlowNode, new_node: ControlFlowNode):
        succ = next(iter(self.graph[node]), None)
        self.graph.add_edge(node, new_node, type=TypeSuccessor.FLOW)
        if succ is not None:
            self.graph.add_edge(new_node, succ, type=TypeSuccessor.JMP)
            self.graph.remove_edge(node, succ)

    def remove_node_from_flow(self, node: ControlFlowNode):
        """For now it's allowed to delete the node that has only one ancestor..."""
        if len(self.graph[node]) != 1:
            print(f"{[str(i) for i in self.graph[node]]}")
            raise Exception(f"Has more than one successor {node}")

        next_node = next(iter(self.graph[node]))
        parents = self.graph.predecessors(node)
        for parent in parents:
            self.graph.add_edge(parent, next_node, **self.graph.edges[parent, node])
        self.graph.remove_node(node)

    def export_to_gdf(self, filename):
        res = "nodedef>name VARCHAR,label VARCHAR\n"
        nodes = [f"0x{i.addr:x},'{i}'" for i in self.graph.nodes]
        res += "\n".join(nodes)
        res += "\n"
        res += "edgedef>node1 VARCHAR,node2 VARCHAR,directed BOOLEAN,label VARCHAR\n"
        edges = [f"0x{n1.addr:x},0x{n2.addr:x},true,{self.graph.edges[n1, n2]['type'].name}"
                 for n1, n2 in self.graph.edges]
        res += "\n".join(edges)
        with open(filename, "w") as f:
            f.write(res)

    def __change_jmp_opcode(self, node, cur_offset, used_insns):
        jmp_node = next((n for n, attrs in self[node].items() if attrs['type'] == TypeSuccessor.JMP), None)
        if jmp_node is None:
            return
            raise Exception

        re_addr = re.compile(r"^j\w{1,3}\s+0x[0-9a-f]+$")
        if re_addr.match(node.str_opcode):
            # not re_jne.match(node.str_opcode):
            # try:
            suc_offset = used_insns[jmp_node]
            # except Exception as e:
            #     print(repr(node))
            #     print(repr(parent))
            #     continue
            #     raise e
            delta = suc_offset - cur_offset - len(node.opcode)
            s, jmp_offset = detect_jmp_size(node)
            try:
                new_offset = st.pack(s, delta)
            except Exception as e:
                raise e

            # print(f"Change node type: from {node}")
            self.code.seek(cur_offset + jmp_offset)
            self.code.write(new_offset)
            self.code.seek(0, io.SEEK_END)

    def save_to_exe(self, filename):
        self.code = io.BytesIO()
        cur_offset = 0
        used_insns = {}
        re_jne = re.compile(r"^jn?e\s+0x[0-9a-f]+$")
        lst_node = None
        for node, _, _ in self.run_through_flow():
            used_insns[node] = self.code.tell()
            self.code.write(node.opcode)
            # if (cur_suc := next(iter(self.graph[node], None))) in used_insns:
            #     offset = used_insns[cur_suc]
            #     new_node
            #     used_insns[new_node] =
            #     code.write(b'\xe9' + '')
        self.code.write(b"\xc9\xc3")  # leave; ret;

        for node, cur_offset in used_insns.items():
            if node.is_jmp:
                self.__change_jmp_opcode(node, cur_offset, used_insns)
                continue
            if node.opcode.startswith(b"\xe8"):
                self.code.seek(cur_offset + 1)
                self.code.write(bytes.fromhex("f00d 4ee4"))
                self.code.seek(0, io.SEEK_END)

        self.code.flush()
        pe = PE.Binary("binary.exe", PE.PE_TYPE.PE32_PLUS)
        section_text                 = PE.Section(".text")
        section_text.content         = self.code.getbuffer()
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
        # print(opcode.opcode, opcode.str_opcode)
        return res, 2
    return res, 1


def symbolization_init(triton, base_stack):
    triton.symbolizeRegister(triton.registers.rax)
    triton.symbolizeRegister(triton.registers.rbx)
    triton.symbolizeRegister(triton.registers.rcx)
    triton.symbolizeRegister(triton.registers.rdx)
    triton.symbolizeRegister(triton.registers.rsp)
    # symbolize the stack area you want to analyze
    for i in range(-0x100, 0x100):
        triton.symbolizeMemory(MemoryAccess(base_stack - i, 1), f'stack_{base_stack + i:#x}')


class AstBuilder():
    def __init__(self, mm: MemMapper):
        self.mm = mm
        # TODO: choose these consts depending on lief info
        self.md = cp.Cs(cp.CS_ARCH_X86, cp.CS_MODE_64)
        self.md.detail = True
        self.cf: ControlFlow = None

    def get_int(self, addr):
        return self.mm[addr:addr+0x20]

    def __process_jmp_int(self, insn):
        addrs = []
        # if conditional jump
        if insn.eflags:
            op = self.op_predict_test(insn)
            if op == OpaquePredicate.SKIP or \
               op == OpaquePredicate.NONE:
                addrs.append((insn.address + insn.size, TypeSuccessor.FLOW))
            if (op == OpaquePredicate.TAKEN or op == OpaquePredicate.NONE) \
               and (insn.op_count(cp.x86.X86_OP_IMM) > 0):
                op = insn.op_find(cp.x86.X86_OP_IMM, 1)
                addrs.append((op.imm, TypeSuccessor.JMP))
        else:
            if insn.op_count(cp.x86.X86_OP_IMM) > 0:
                op = insn.op_find(cp.x86.X86_OP_IMM, 1)
                addrs.append((op.imm, TypeSuccessor.JMP))
        return addrs

    def op_predict_test(self, insn):
        def iter_parents(opcode, count=1):
            get_nxt_parent = lambda node: next(self.cf.predecessors(node), None)
            cur = count
            parent = opcode
            while cur > 0:
                parent = get_nxt_parent(parent)
                yield parent
                cur -= 1
        cur_node = ControlFlowNode(insn)
        trace_to_symbolic = [parent for parent in iter_parents(cur_node)][::-1] + [cur_node]
        if not trace_to_symbolic[0].is_jmp:
            return self.__symbolic_test(insn)
        else:
            return OpaquePredicate.NONE

    def __symbolic_test(self, insn):
        def iter_parents(opcode, count=1):
            get_nxt_parent = lambda node: next(self.cf.predecessors(node), None)
            cur = count
            parent = opcode
            while cur > 0:
                parent = get_nxt_parent(parent)
                yield parent
                cur -= 1
        cur_node = ControlFlowNode(insn)
        trace_to_symbolic = [parent for parent in iter_parents(cur_node)][::-1] + [cur_node]
        triton = TritonContext()
        triton.setArchitecture(ARCH.X86_64)
        rsp_val = 0x7ffc0000
        symbolization_init(triton, rsp_val)
        ctx = triton.getAstContext()
        triton.setConcreteRegisterValue(triton.registers.esp, rsp_val)
        lst_ins = None

        for opcode in trace_to_symbolic:
            # print(opcode)
            lst_ins = opcode.process_triton(triton)
        op_ast = triton.getPathPredicate()
        # print(op_ast)
        model = triton.getModel(ctx.lnot(op_ast))

        if not model:
            # print(model)
            if lst_ins.isConditionTaken():
                # print(f"Taken 0x{insn.address:08x}")
                return OpaquePredicate.TAKEN
            else:
                # print(f"Skip 0x{insn.address:08x}")
                return OpaquePredicate.SKIP
        else:
            # print(f"NotP 0x{insn.address:08x}")
            return OpaquePredicate.NONE

    # TODO: need some fixes
    def start_execution(self, entrypoint):
        code = self.get_int(entrypoint)
        stack = [(None, None, (code, entrypoint))]
        limit = 500000
        debug = False
        while limit > 0 and stack:
            limit -= 1
            parent_node, go_type, data = stack.pop()
            # m = self.md.disasm(*data)
            # if parent_node is not None and parent_node.addr == 0x140026ce2:
            #     print(data[0].hex())
            #     print(list(m))
            #     print("Here our address")
            insn = next(self.md.disasm(*data), None)
            # print_insn_detail(cp.CS_MODE_64, insn)
            if insn is None:
                print("This should not happen")
                continue
            cur_node = ControlFlowNode(insn)
            if parent_node is None:
                print("This must be only once")
                self.cf = ControlFlow(cur_node)
            else:
                self.cf.create_edge(parent_node, cur_node, go_type)
            if Insn_groups.JMP.value in insn.groups:
                addrs = self.__process_jmp_int(insn)
            elif Insn_groups.RET.value in insn.groups:
                continue
            else:
                addrs = [(insn.address + insn.size, TypeSuccessor.FLOW)]
            if data[1] == 0x140026ce2:
                debug = True
                print("Printing left address")
                print(addrs)
            non_existing_addrs = []
            for addr, type_ in addrs:
                if addr in self.cf:
                    if debug:
                        print("Already exists")
                    self.cf.create_edge(cur_node, self.cf[addr], type_)
                else:
                    if debug:
                        print("Not exists")
                    non_existing_addrs.append((addr, type_))
            news = [(cur_node, type_, (self.get_int(addr), addr)) for addr, type_ in non_existing_addrs]
            if debug:
                print(news)
                debug = False
            stack += news
        print(f"Exit cycle with {limit=} and {stack=}")


class Section():
    def __init__(self, section, imagebase):
        self.va = section.virtual_address + imagebase
        self.end_va = self.va + section.size
        self.data = bytes(section.content)

    def __getitem__(self, key):
        if type(key) is slice:
            attrs = ["start", "stop", "step"]
            new_params = [attr - self.va
                          if (attr := getattr(key, i)) is not None
                          else attr
                          for i in attrs]
            cur_key = slice(*new_params)
        elif type(key) is int:
            cur_key = key - self.va
        res = self.data[cur_key]
        return res


class MemMapper():
    def __init__(self, lp):
        self.lp = lp
        imagebase = self.lp.optional_header.imagebase
        self.sections = [Section(section, imagebase) for section in self.lp.sections]

    def __getitem__(self, key):
        if type(key) is slice:
            start_idx = key.start
        elif type(key) is int:
            start_idx = key
        section = next((i for i in self.sections if i.va <= start_idx <= i.end_va), None)
        if section is None:
            raise Exception("section not found")
        return section[key]


def open_PE_file(filename):
    mm = MemMapper(lief.parse(filename))
    return mm


def open_BIN_file(filename):
    with open(filename, "rb") as f:
        a = f.read()
    mm = a
    return mm


def main():
    address = [
        (0x140024168, "just_entrypoint"),
    ]

    target_func_addr, suffix = address[-1]
    mm = open_PE_file("sakura-agent.exe.bin")

    # address_bin = [
    #     (0,     "17_just_start_addr"),
    # ]
    # target_func_addr, suffix = address_bin[1]
    # mm = open_BIN_file("output_dir/deced_buf_17")
    astb = AstBuilder(mm)
    astb.start_execution(target_func_addr)
    astb.cf.export_to_gdf(f"exec_{target_func_addr:x}_{suffix}.gdf")
    astb.cf.process_predicates()
    astb.cf.clean_jmps()
    astb.cf.replace_all_near_jmps()
    astb.cf.export_to_gdf(f"cleaned_{target_func_addr:x}_{suffix}.gdf")
    astb.cf.save_to_txt(f"cleaned_{target_func_addr:x}_{suffix}.txt")
    astb.cf.save_to_exe(f"just_one_func_{target_func_addr:x}_{suffix}.bin")


def print_insn_detail(mode, insn):
    print(insn.bytes.hex())

    def print_string_hex(comment, str):
        print(comment, end=' '),
        for c in str:
            print("0x%02x " % c, end=''),
        print()

    print(dir(insn))
    # print address, mnemonic and operands
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

    print("Groups:", ", ".join( f"{gid, insn.group_name(gid)}" for gid in insn.groups))
    # "data" instruction generated by SKIPDATA option has no detail
    if insn.id == 0:
        return

    # print instruction prefix
    print_string_hex("\tPrefix:", insn.prefix)

    # print instruction's opcode
    print_string_hex("\tOpcode:", insn.opcode)

    # print operand's REX prefix (non-zero value is relavant for x86_64 instructions)
    print("\trex: 0x%x" % (insn.rex))

    # print operand's address size
    print("\taddr_size: %u" % (insn.addr_size))

    # print modRM byte
    print("\tmodrm: 0x%x" % (insn.modrm))

    # print modRM offset
    if insn.modrm_offset != 0:
        print("\tmodrm_offset: 0x%x" % (insn.modrm_offset))

    # print displacement value
    print("\tdisp: 0x%s" % insn.disp)

    # print displacement offset (offset into instruction bytes)
    if insn.disp_offset != 0:
        print("\tdisp_offset: 0x%x" % (insn.disp_offset))

    # print displacement size
    if insn.disp_size != 0:
        print("\tdisp_size: 0x%x" % (insn.disp_size))

    # XOP CC type
    if insn.xop_cc != cp.x86.X86_XOP_CC_INVALID:
        print("\txop_cc: %u" % (insn.xop_cc))

    # SSE CC type
    if insn.sse_cc != cp.x86.X86_SSE_CC_INVALID:
        print("\tsse_cc: %u" % (insn.sse_cc))

    # AVX CC type
    if insn.avx_cc != cp.x86.X86_AVX_CC_INVALID:
        print("\tavx_cc: %u" % (insn.avx_cc))

    # AVX Suppress All Exception
    if insn.avx_sae:
        print("\tavx_sae: TRUE")

    # AVX Rounding Mode type
    if insn.avx_rm != cp.x86.X86_AVX_RM_INVALID:
        print("\tavx_rm: %u" % (insn.avx_rm))

    count = insn.op_count(cp.x86.X86_OP_IMM)
    if count > 0:
        print("\timm_count: %u" % count)
        for i in range(count):
            op = insn.op_find(cp.x86.X86_OP_IMM, i + 1)
            print(f"\t\timms[{i+1}]: 0x{op.imm:08x}")
            if insn.imm_offset != 0:
                print("\timm_offset: 0x%x" % (insn.imm_offset))
            if insn.imm_size != 0:
                print("\timm_size: 0x%x" % (insn.imm_size))

    if len(insn.operands) > 0:
        print("\top_count: %u" % len(insn.operands))
        c = -1
        for i in insn.operands:
            c += 1
            if i.type == cp.x86.X86_OP_REG:
                print(f"\t\toperands[{c}].type: REG = {insn.reg_name(i.reg)}")
            if i.type == cp.x86.X86_OP_IMM:
                print(f"\t\toperands[{c}].type: IMM = 0x{i.imm:08x}")
            if i.type == cp.x86.X86_OP_MEM:
                print("\t\toperands[%u].type: MEM" % c)
                if i.mem.segment != 0:
                    print("\t\t\toperands[%u].mem.segment: REG = %s" % (c, insn.reg_name(i.mem.segment)))
                if i.mem.base != 0:
                    print("\t\t\toperands[%u].mem.base: REG = %s" % (c, insn.reg_name(i.mem.base)))
                if i.mem.index != 0:
                    print("\t\t\toperands[%u].mem.index: REG = %s" % (c, insn.reg_name(i.mem.index)))
                if i.mem.scale != 1:
                    print("\t\t\toperands[%u].mem.scale: %u" % (c, i.mem.scale))
                if i.mem.disp != 0:
                    print(f"\t\t\toperands[{c}].mem.disp: 0x{i.mem.disp:08x}")

            # AVX broadcast type
            if i.avx_bcast != cp.x86.X86_AVX_BCAST_INVALID:
                print("\t\toperands[%u].avx_bcast: %u" % (c, i.avx_bcast))

            # AVX zero opmask {z}
            if i.avx_zero_opmask:
                print(f"\t\toperands[{c}].avx_zero_opmask: TRUE")

            print("\t\toperands[%u].size: %u" % (c, i.size))

            if i.access == cp.CS_AC_READ:
                print("\t\toperands[%u].access: READ\n" % (c))
            elif i.access == cp.CS_AC_WRITE:
                print("\t\toperands[%u].access: WRITE\n" % (c))
            elif i.access == cp.CS_AC_READ | cp.CS_AC_WRITE:
                print("\t\toperands[%u].access: READ | WRITE\n" % (c))

    (regs_read, regs_write) = insn.regs_access()

    if len(regs_read) > 0:
        print("\tRegisters read:", end="")
        for r in regs_read:
            print(" %s" % (insn.reg_name(r)), end="")
        print("")

    if len(regs_write) > 0:
        print("\tRegisters modified:", end="")
        for r in regs_write:
            print(" %s" % (insn.reg_name(r)), end="")
        print("")

    if insn.eflags:
        updated_flags = []
        for i in range(0, 46):
            if insn.eflags & (1 << i):
                updated_flags.append(get_eflag_name(1 << i))
        print("\tEFLAGS: %s" % (','.join(p for p in updated_flags)))


def get_eflag_name(eflag):
    if eflag == cp.x86.X86_EFLAGS_UNDEFINED_OF:
        return "UNDEF_OF"
    elif eflag == cp.x86.X86_EFLAGS_UNDEFINED_SF:
        return "UNDEF_SF"
    elif eflag == cp.x86.X86_EFLAGS_UNDEFINED_ZF:
        return "UNDEF_ZF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_AF:
        return "MOD_AF"
    elif eflag == cp.x86.X86_EFLAGS_UNDEFINED_PF:
        return "UNDEF_PF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_CF:
        return "MOD_CF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_SF:
        return "MOD_SF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_ZF:
        return "MOD_ZF"
    elif eflag == cp.x86.X86_EFLAGS_UNDEFINED_AF:
        return "UNDEF_AF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_PF:
        return "MOD_PF"
    elif eflag == cp.x86.X86_EFLAGS_UNDEFINED_CF:
        return "UNDEF_CF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_OF:
        return "MOD_OF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_OF:
        return "RESET_OF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_CF:
        return "RESET_CF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_DF:
        return "RESET_DF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_IF:
        return "RESET_IF"
    elif eflag == cp.x86.X86_EFLAGS_TEST_OF:
        return "TEST_OF"
    elif eflag == cp.x86.X86_EFLAGS_TEST_SF:
        return "TEST_SF"
    elif eflag == cp.x86.X86_EFLAGS_TEST_ZF:
        return "TEST_ZF"
    elif eflag == cp.x86.X86_EFLAGS_TEST_PF:
        return "TEST_PF"
    elif eflag == cp.x86.X86_EFLAGS_TEST_CF:
        return "TEST_CF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_SF:
        return "RESET_SF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_AF:
        return "RESET_AF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_TF:
        return "RESET_TF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_NT:
        return "RESET_NT"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_OF:
        return "PRIOR_OF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_SF:
        return "PRIOR_SF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_ZF:
        return "PRIOR_ZF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_AF:
        return "PRIOR_AF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_PF:
        return "PRIOR_PF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_CF:
        return "PRIOR_CF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_TF:
        return "PRIOR_TF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_IF:
        return "PRIOR_IF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_DF:
        return "PRIOR_DF"
    elif eflag == cp.x86.X86_EFLAGS_TEST_NT:
        return "TEST_NT"
    elif eflag == cp.x86.X86_EFLAGS_TEST_DF:
        return "TEST_DF"
    elif eflag == cp.x86.X86_EFLAGS_RESET_PF:
        return "RESET_PF"
    elif eflag == cp.x86.X86_EFLAGS_PRIOR_NT:
        return "PRIOR_NT"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_TF:
        return "MOD_TF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_IF:
        return "MOD_IF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_DF:
        return "MOD_DF"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_NT:
        return "MOD_NT"
    elif eflag == cp.x86.X86_EFLAGS_MODIFY_RF:
        return "MOD_RF"
    elif eflag == cp.x86.X86_EFLAGS_SET_CF:
        return "SET_CF"
    elif eflag == cp.x86.X86_EFLAGS_SET_DF:
        return "SET_DF"
    elif eflag == cp.x86.X86_EFLAGS_SET_IF:
        return "SET_IF"
    else:
        return None


if __name__ == '__main__':
    main()
