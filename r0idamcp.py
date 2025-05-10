from fastmcp import FastMCP
import threading
import asyncio
import functools
import logging
import queue
from typing import Any, Callable, Dict, List, get_type_hints, TypedDict, Optional, Annotated, TypeVar, Generic
import struct
import sys
from pydantic import Field
import re
import ida_kernwin
import ida_idaapi
import ida_funcs
import idautils
import idaapi
import ida_nalt
import idc
import ida_hexrays
import ida_lines
import ida_xref
import ida_entry
import ida_typeinf
import ida_segment
import ida_ua
import ida_bytes

class IDASyncError(Exception):
    pass
class IDASafety:
    ida_kernwin.MFF_READ
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE
call_stack = queue.LifoQueue()
class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str
class Function(TypedDict):
    address: str
    name: str
    size: str
class IDAError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
    @property
    def message(self) -> str:
        return self.args[0]
logger = logging.getLogger(__name__)
def sync_wrapper(ff, safety_mode: IDASafety):
    """
    Call a function ff with a specific IDA safety_mode.
    """
    #logger.debug('sync_wrapper: {}, {}'.format(ff.__name__, safety_mode))

    if safety_mode not in [IDASafety.SAFE_READ, IDASafety.SAFE_WRITE]:
        error_str = 'Invalid safety mode {} over function {}'\
                .format(safety_mode, ff.__name__)
        logger.error(error_str)
        raise IDASyncError(error_str)

    # No safety level is set up:
    res_container = queue.Queue()

    def runned():
        #logger.debug('Inside runned')

        # Make sure that we are not already inside a sync_wrapper:
        if not call_stack.empty():
            last_func_name = call_stack.get()
            error_str = ('Call stack is not empty while calling the '
                'function {} from {}').format(ff.__name__, last_func_name)
            #logger.error(error_str)
            raise IDASyncError(error_str)

        call_stack.put((ff.__name__))
        try:
            res_container.put(ff())
        except Exception as x:
            res_container.put(x)
        finally:
            call_stack.get()
            #logger.debug('Finished runned')

    ret_val = idaapi.execute_sync(runned, safety_mode)
    res = res_container.get()
    if isinstance(res, Exception):
        raise res
    return res

def get_image_size():
    try:
        # https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html
        info = idaapi.get_inf_structure()
        omin_ea = info.omin_ea
        omax_ea = info.omax_ea
    except AttributeError:
        import ida_ida
        omin_ea = ida_ida.inf_get_omin_ea()
        omax_ea = ida_ida.inf_get_omax_ea()
    # Bad heuristic for image size (bad if the relocations are the last section)
    image_size = omax_ea - omin_ea
    # Try to extract it from the PE header
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size


def idaread(f):
    """
    decorator for marking a function as reading from the IDB.
    schedules a request to be made in the main IDA loop to avoid
      inconsistent results.
    MFF_READ constant via: http://www.openrce.org/forums/posts/1827
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_READ)
    return wrapper
def idawrite(f):
    """
    decorator for marking a function as modifying the IDB.
    schedules a request to be made in the main IDA loop to avoid IDB corruption.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        ff = functools.partial(f, *args, **kwargs)
        ff.__name__ = f.__name__
        return sync_wrapper(ff, idaapi.MFF_WRITE)
    return wrapper


def is_window_active():
    """Returns whether IDA is currently active"""
    try:
        from PyQt5.QtWidgets import QApplication
    except ImportError:
        return False

    app = QApplication.instance()
    if app is None:
        return False

    for widget in app.topLevelWidgets():
        if widget.isActiveWindow():
            return True
    return False


@idaread
def get_metadata_real() -> Metadata:
    """Get metadata about the current IDB"""
    # Fat Mach-O binaries can return a None hash:
    # https://github.com/mrexodia/ida-pro-mcp/issues/26
    def hash(f):
        try:
            return f().hex()
        except:
            return None
    return {
        "path": idaapi.get_input_file_path(),
        "module": idaapi.get_root_filename(),
        "base": hex(idaapi.get_imagebase()),
        "size": hex(get_image_size()),
        "md5": hash(ida_nalt.retrieve_input_file_md5),
        "sha256": hash(ida_nalt.retrieve_input_file_sha256),
        "crc32": hex(ida_nalt.retrieve_input_file_crc32()),
        "filesize": hex(ida_nalt.retrieve_input_file_size()),
    }

def get_function(address: int, *, raise_error=True) -> Function:
    fn = idaapi.get_func(address)
    if fn is None:
        if raise_error:
            raise IDAError(f"No function found at address {hex(address)}")
        return None
    try:
        name = fn.get_name()
    except AttributeError:
        name = ida_funcs.get_func_name(fn.start_ea)
    return {
        "address": hex(fn.start_ea),
        "name": name,
        "size": hex(fn.end_ea - fn.start_ea),
    }
DEMANGLED_TO_EA = {}
def create_demangled_to_ea_map():
    for ea in idautils.Functions():
        # Get the function name and demangle it
        # MNG_NODEFINIT inhibits everything except the main name
        # where default demangling adds the function signature
        # and decorators (if any)
        demangled = idaapi.demangle_name(
            idc.get_name(ea, 0), idaapi.MNG_NODEFINIT)
        if demangled:
            DEMANGLED_TO_EA[demangled] = ea
def parse_address(address: str) -> int:
    try:
        return int(address, 0)
    except ValueError:
        for ch in address:
            if ch not in "0123456789abcdefABCDEF":
                raise IDAError(f"Failed to parse address: {address}")
        raise IDAError(f"Failed to parse address (missing 0x prefix): {address}")

@idaread
def get_function_by_name_real(name: Annotated[str, "Name of the function to get"]) -> Function:
    """Get a function by its name"""
    function_address = idaapi.get_name_ea(idaapi.BADADDR, name)
    if function_address == idaapi.BADADDR:
        # If map has not been created yet, create it
        if len(DEMANGLED_TO_EA) == 0:
            create_demangled_to_ea_map()
        # Try to find the function in the map, else raise an error
        if name in DEMANGLED_TO_EA:
            function_address = DEMANGLED_TO_EA[name]
        else:
            raise IDAError(f"No function found with name {name}")
    return get_function(function_address)

@idaread
def get_function_by_address_real(    address: Annotated[str, "Address of the function to get"]) -> Function:
    """Get a function by its address"""
    return get_function(parse_address(address))

@idaread
def get_current_address_real() -> str:
    """Get the address currently selected by the user"""
    return hex(idaapi.get_screen_ea())

@idaread
def get_current_function_real() -> Optional[Function]:
    """Get the function currently selected by the user"""
    return get_function(idaapi.get_screen_ea())

class ConvertedNumber(TypedDict):
    decimal: str
    hexadecimal: str
    bytes: str
    ascii: Optional[str]
    binary: str

def convert_number_real(
    text: Annotated[str, "Textual representation of the number to convert"],
    size: Annotated[Optional[int], "Size of the variable in bytes"],
) -> ConvertedNumber:
    """Convert a number (decimal, hexadecimal) to different representations"""
    try:
        value = int(text, 0)
    except ValueError:
        raise IDAError(f"Invalid number: {text}")

    # Estimate the size of the number
    if not size:
        size = 0
        n = abs(value)
        while n:
            size += 1
            n >>= 1
        size += 7
        size //= 8

    # Convert the number to bytes
    try:
        bytes = value.to_bytes(size, "little", signed=True)
    except OverflowError:
        raise IDAError(f"Number {text} is too big for {size} bytes")

    # Convert the bytes to ASCII
    ascii = ""
    for byte in bytes.rstrip(b"\x00"):
        if byte >= 32 and byte <= 126:
            ascii += chr(byte)
        else:
            ascii = None
            break

    return {
        "decimal": str(value),
        "hexadecimal": hex(value),
        "bytes": bytes.hex(" "),
        "ascii": ascii,
        "binary": bin(value)
    }

T = TypeVar("T")

class Page(TypedDict, Generic[T]):
    data: list[T]
    next_offset: Optional[int]

def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    if count == 0:
        count = len(data)
    next_offset = offset + count
    if next_offset >= len(data):
        next_offset = None
    return {
        "data": data[offset:offset+count],
        "next_offset": next_offset,
    }

@idaread
def list_functions_real(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of functions to list (100 is a good default, 0 means remainder)"],
) -> Page[Function]:
    """List all functions in the database (paginated)"""
    functions = [get_function(address) for address in idautils.Functions()]
    return paginate(functions, offset, count)

class String(TypedDict):
    address: str
    length: int
    type: str
    string: str
def get_strings() -> list[String]:
    strings = []
    for item in idautils.Strings():
        string_type = "C" if item.strtype == 0 else "Unicode"
        try:
            string = str(item)
            if string:
                strings.append({
                    "address": hex(item.ea),
                    "length": item.length,
                    "type": string_type,
                    "string": string
                })
        except:
            continue
    return strings
@idaread
def list_strings_real(
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
) -> Page[String]:
    """List all strings in the database (paginated)"""
    strings = get_strings()
    return paginate(strings, offset, count)
@idaread
def search_strings_real(
        pattern_str: Annotated[str, "The regular expression to match((The generated regular expression includes case by default))"],
        offset: Annotated[int, "Offset to start listing from (start at 0)"],
        count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
) -> Page[String]:
    """Search for strings that satisfy a regular expression"""
    strings = get_strings()
    try:
        pattern = re.compile(pattern_str)
    except Exception as e:
        raise ValueError(f"Regular expression syntax error, reason is {e}")
    try:
        matched_strings = [s for s in strings if s["string"] and re.search(pattern, s["string"])]
    except Exception as e:
        raise ValueError(f"The regular match failed, reason is {e}")
    return paginate(matched_strings, offset, count)
@idaread
def search_strings_real(
    pattern: Annotated[str, "Substring to search for in strings"],
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
) -> Page[String]:
    """Search for strings containing the given pattern (case-insensitive)"""
    strings = get_strings()
    matched_strings = [s for s in strings if pattern.lower() in s["string"].lower()]
    return paginate(matched_strings, offset, count)

def decompile_checked(address: int) -> ida_hexrays.cfunc_t:
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError("Hex-Rays decompiler is not available")
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(address, error, ida_hexrays.DECOMP_WARNINGS)
    if not cfunc:
        message = f"Decompilation failed at {hex(address)}"
        if error.str:
            message += f": {error.str}"
        if error.errea != idaapi.BADADDR:
            message += f" (address: {hex(error.errea)})"
        raise IDAError(message)
    return cfunc
@idaread
def decompile_function_real(
    address: Annotated[str, "Address of the function to decompile"]
) -> str:
    """Decompile a function at the given address"""
    address = parse_address(address)
    cfunc = decompile_checked(address)
    if is_window_active():
        ida_hexrays.open_pseudocode(address, ida_hexrays.OPF_REUSE)
    sv = cfunc.get_pseudocode()
    pseudocode = ""
    for i, sl in enumerate(sv):
        sl: ida_kernwin.simpleline_t
        item = ida_hexrays.ctree_item_t()
        addr = None if i > 0 else cfunc.entry_ea
        if cfunc.get_line_item(sl.line, 0, False, None, item, None):
            ds = item.dstr().split(": ")
            if len(ds) == 2:
                try:
                    addr = int(ds[0], 16)
                except ValueError:
                    pass
        line = ida_lines.tag_remove(sl.line)
        if len(pseudocode) > 0:
            pseudocode += "\n"
        if not addr:
            pseudocode += f"/* line: {i} */ {line}"
        else:
            pseudocode += f"/* line: {i}, address: {hex(addr)} */ {line}"
    return pseudocode

@idaread
def disassemble_function_real(
    start_address: Annotated[str, "Address of the function to disassemble"]
) -> str:
    """Get assembly code (address: instruction; comment) for a function"""
    start = parse_address(start_address)
    func = idaapi.get_func(start)
    if not func:
        raise IDAError(f"No function found containing address {start_address}")
    if is_window_active():
        ida_kernwin.jumpto(start)

    # TODO: add labels and limit the maximum number of instructions
    disassembly = ""
    for address in ida_funcs.func_item_iterator_t(func):
        if len(disassembly) > 0:
            disassembly += "\n"
        disassembly += f"{hex(address)}: "
        disassembly += idaapi.generate_disasm_line(address, idaapi.GENDSM_REMOVE_TAGS)
        comment = idaapi.get_cmt(address, False)
        if not comment:
            comment = idaapi.get_cmt(address, True)
        if comment:
            disassembly += f"; {comment}"
    return disassembly

class Xref(TypedDict):
    address: str
    type: str
    function: Optional[Function]
@idaread
def get_xrefs_to_real(
    address: Annotated[str, "Address to get cross references to"]
) -> list[Xref]:
    """Get all cross references to the given address"""
    xrefs = []
    xref: ida_xref.xrefblk_t
    for xref in idautils.XrefsTo(parse_address(address)):
        xrefs.append({
            "address": hex(xref.frm),
            "type": "code" if xref.iscode else "data",
            "function": get_function(xref.frm, raise_error=False),
        })
    return xrefs
@idaread
def get_entry_points_real() -> list[Function]:
    """Get all entry points in the database"""
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        address = ida_entry.get_entry(ordinal)
        func = get_function(address, raise_error=False)
        if func is not None:
            result.append(func)
    return result
@idaread
def get_segments_real() -> List[Dict[str, Any]]:
    segments = []
    n = 0
    seg = ida_segment.getnseg(n)
    while seg:
        segments.append(
            {
                "start": seg.start_ea,
                "end": seg.end_ea,
                "name": ida_segment.get_segm_name(seg),
                "class": ida_segment.get_segm_class(seg),
                "perm": seg.perm,
                "bitness": seg.bitness,
                "align": seg.align,
                "comb": seg.comb,
                "type": seg.type,
                "sel": seg.sel,
                "flags": seg.flags,
            }
        )
        n += 1
        seg = ida_segment.getnseg(n)
    return segments
@idaread
def get_instruction_length_real(address: int) -> int:
    """
    Retrieves the length (in bytes) of the instruction at the specified address.
    Args:
        address: The address of the instruction.
    Returns:
        The length (in bytes) of the instruction.  Returns 0 if the instruction cannot be decoded.
    """
    try:
        # Create an insn_t object to store instruction information.
        insn = ida_ua.insn_t()
        # Decode the instruction.
        length = ida_ua.decode_insn(insn, address)
        if length == 0:
            print(f"Failed to decode instruction at address {hex(address)}")
            return 0
        return length
    except Exception as e:
        print(f"Error getting instruction length: {str(e)}")
        return 0
@idaread
def get_bytes_real(ea: int, size: int) -> List[int]:
    try:
        result = [ida_bytes.get_byte(ea + i) for i in range(size)]
        return result
    except Exception as e:
        print(f"Error in get_bytes: {str(e)}")
        return {"error": str(e)}

@idawrite
def set_comment_real(
    address: Annotated[str, "Address in the function to set the comment for"],
    comment: Annotated[str, "Comment text"]
) -> str:
    """Set a comment for a given address in the function disassembly and pseudocode
    
    Returns:
        str: Success message if comment was set successfully, or error message if failed
    """
    address = parse_address(address)

    # Set disassembly comment first
    if not idaapi.set_cmt(address, comment, False):
        raise IDAError(f"Failed to set disassembly comment at {hex(address)}")
    
    success_msg = f"Successfully set disassembly comment at {hex(address)}"

    # Reference: https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/
    # Check if the address corresponds to a line in decompiled code
    cfunc = decompile_checked(address)

    # Special case for function entry comments
    if address == cfunc.entry_ea:
        idc.set_func_cmt(address, comment, True)
        cfunc.refresh_func_ctext()
        return f"{success_msg} and function entry comment"

    eamap = cfunc.get_eamap()
    if address not in eamap:
        print(f"Failed to set decompiler comment at {hex(address)}")
        return f"{success_msg}, but failed to set decompiler comment (address not in eamap)"

    nearest_ea = eamap[address][0].ea

    # Remove existing orphan comments
    if cfunc.has_orphan_cmts():
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()

    # Set the comment by trying all possible item types
    tl = idaapi.treeloc_t()
    tl.ea = nearest_ea
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()
        if not cfunc.has_orphan_cmts():
            return f"{success_msg} and decompiler comment"
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()
    
    print(f"Failed to set decompiler comment at {hex(address)}")
    return f"{success_msg}, but failed to set decompiler comment (all item types tried)"

def refresh_decompiler_widget():
    widget = ida_kernwin.get_current_widget()
    if widget is not None:
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu is not None:
            vu.refresh_ctext()

def refresh_decompiler_ctext(function_address: int):
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(function_address, error, ida_hexrays.DECOMP_WARNINGS)
    if cfunc:
        cfunc.refresh_func_ctext()
@idawrite
def rename_local_variable_real(
    function_address: Annotated[str, "Address of the function containing the variable"],
    old_name: Annotated[str, "Current name of the variable"],
    new_name: Annotated[str, "New name for the variable (empty for a default name)"]
) -> str:
    """Rename a local variable in a function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    
    # 获取函数的局部变量列表
    cfunc = idaapi.decompile(func.start_ea)
    if not cfunc:
        raise IDAError(f"Failed to decompile function at address {function_address}")
    lvars = cfunc.get_lvars()
    
    # 检测新变量名是否与已存在的局部变量名重名
    for lvar in lvars:
        if lvar.name == new_name:
            return f"Variable name '{new_name}' already exists in function {hex(func.start_ea)}. Please choose a different name."
    
    if not ida_hexrays.rename_lvar(func.start_ea, old_name, new_name):
        raise IDAError(f"Failed to rename local variable {old_name} in function {hex(func.start_ea)}")
    refresh_decompiler_ctext(func.start_ea)
    return f"Successfully renamed local variable {old_name} to {new_name} in function {hex(func.start_ea)}"
    
class my_modifier_t(ida_hexrays.user_lvar_modifier_t):
    def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
        ida_hexrays.user_lvar_modifier_t.__init__(self)
        self.var_name = var_name
        self.new_type = new_type

    def modify_lvars(self, lvars):
        for lvar_saved in lvars.lvvec:
            lvar_saved: ida_hexrays.lvar_saved_info_t
            if lvar_saved.name == self.var_name:
                lvar_saved.type = self.new_type
                return True
        return False

@idawrite
def set_local_variable_type_real(
    function_address: Annotated[str, "Address of the function containing the variable"],
    variable_name: Annotated[str, "Name of the variable"],
    new_type: Annotated[str, "New type for the variable"]
):
    """Set a local variable's type"""
    try:
        # Some versions of IDA don't support this constructor
        new_tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
    except Exception:
        try:
            new_tif = ida_typeinf.tinfo_t()
            # parse_decl requires semicolon for the type
            ida_typeinf.parse_decl(new_tif, None, new_type+";", ida_typeinf.PT_SIL)
        except Exception:
            raise IDAError(f"Failed to parse type: {new_type}")
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not ida_hexrays.rename_lvar(func.start_ea, variable_name, variable_name):
        raise IDAError(f"Failed to find local variable: {variable_name}")
    modifier = my_modifier_t(variable_name, new_tif)
    if not ida_hexrays.modify_user_lvars(func.start_ea, modifier):
        raise IDAError(f"Failed to modify local variable: {variable_name}")
    refresh_decompiler_ctext(func.start_ea)


@idawrite
def rename_global_variable_real(
    old_name: Annotated[str, "Current name of the global variable"],
    new_name: Annotated[str, "New name for the global variable (empty for a default name)"]
):
    """Rename a global variable"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)
    if not idaapi.set_name(ea, new_name):
        raise IDAError(f"Failed to rename global variable {old_name} to {new_name}")
    refresh_decompiler_ctext(ea)
@idawrite
def set_global_variable_type_real(
    variable_name: Annotated[str, "Name of the global variable"],
    new_type: Annotated[str, "New type for the variable"]
):
    """Set a global variable's type"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
    if not tif:
        raise IDAError(f"Parsed declaration is not a variable type")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL):
        raise IDAError(f"Failed to apply type")
@idawrite
def rename_function_real(
    function_address: Annotated[str, "Address of the function to rename"],
    new_name: Annotated[str, "New name for the function (empty for a default name)"]
):
    """Rename a function"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    if not idaapi.set_name(func.start_ea, new_name):
        raise IDAError(f"Failed to rename function {hex(func.start_ea)} to {new_name}")
    refresh_decompiler_ctext(func.start_ea)
@idawrite
def set_function_prototype_real(
    function_address: Annotated[str, "Address of the function"],
    prototype: Annotated[str, "New function prototype"]
) -> str:
    """Set a function's prototype"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError(f"No function found at address {function_address}")
    try:
        tif = ida_typeinf.tinfo_t(prototype, None, ida_typeinf.PT_SIL)
        if not tif.is_func():
            raise IDAError(f"Parsed declaration is not a function type")
        if not ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL):
            raise IDAError(f"Failed to apply type")
        refresh_decompiler_ctext(func.start_ea)
    except Exception as e:
        raise IDAError(f"Failed to parse prototype string: {prototype}")
# NOTE: This is extremely hacky, but necessary to get errors out of IDA
def parse_decls_ctypes(decls: str, hti_flags: int) -> tuple[int, str]:
    if sys.platform == "win32":
        import ctypes
        assert isinstance(decls, str), "decls must be a string"
        assert isinstance(hti_flags, int), "hti_flags must be an int"
        c_decls = decls.encode("utf-8")
        c_til = None
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
        ida_dll.parse_decls.restype = ctypes.c_int

        messages = []
        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes):
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                messages.append(formatted.decode("utf-8"))
                return len(formatted) + 1
            else:
                messages.append(f"unsupported magic_printer fmt: {repr(fmt)}")
                return 0

        errors = ida_dll.parse_decls(c_til, c_decls, magic_printer, hti_flags)
    else:
        # NOTE: The approach above could also work on other platforms, but it's
        # not been tested and there are differences in the vararg ABIs.
        errors = ida_typeinf.parse_decls(None, decls, False, hti_flags)
        messages = []
    return errors, messages
@idawrite
def declare_c_type_real(
    c_declaration: Annotated[str, "C declaration of the type. Examples include: typedef int foo_t; struct bar { int a; bool b; };"],
):
    """Create or update a local type from a C declaration"""
    # PT_SIL: Suppress warning dialogs (although it seems unnecessary here)
    # PT_EMPTY: Allow empty types (also unnecessary?)
    # PT_TYP: Print back status messages with struct tags
    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
    errors, messages = parse_decls_ctypes(c_declaration, flags)

    pretty_messages = "\n".join(messages)
    if errors > 0:
        raise IDAError(f"Failed to parse type:\n{c_declaration}\n\nErrors:\n{pretty_messages}")
    return f"success\n\nInfo:\n{pretty_messages}"




# mcp = FastMCP(name="My MCP Server",host=0.0.0.0,port=8888)
# Configure during initialization
mcp = FastMCP(name="myServer")


@mcp.tool()
def greet(name: str) -> str:
    return f"Hello roysue, {name}!"

@mcp.tool()
def check_connection() -> str:
    """Check if the IDA plugin is running"""
    try:
        metadata = get_metadata_real()
        return f"Successfully connected to IDA Pro (open file: {metadata['module']})"
    except Exception as e:
        if sys.platform == "darwin":
            shortcut = "Ctrl+Option+M"
        else:
            shortcut = "Ctrl+Alt+M"
        return f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?"

@mcp.tool()
def get_metadata() -> Metadata:
    """Get metadata about the current IDB"""
    return get_metadata_real()
@mcp.tool()
def get_function_by_name(name: Annotated[str, Field(description='Name of the function to get')]) -> Function:
    """Get a function by its name"""
    return get_function_by_name_real(name)
@mcp.tool()
def get_function_by_address(address: Annotated[str, Field(description='Address of the function to get')]) -> Function:
    """Get a function by its address"""
    return get_function_by_address_real(address)

@mcp.tool()
def get_current_address() -> str:
    """Get the address currently selected by the user"""
    return get_current_address_real()

@mcp.tool()
def get_current_function() -> Optional[Function]:
    """Get the function currently selected by the user"""
    return get_current_function_real()

@mcp.tool()
def convert_number(text: Annotated[str, Field(description='Textual representation of the number to convert')], size: Annotated[Optional[int], Field(description='Size of the variable in bytes')]) -> ConvertedNumber:
    """Convert a number (decimal, hexadecimal) to different representations"""
    return convert_number_real(text, size)

@mcp.tool()
def list_functions(offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of functions to list (100 is a good default, 0 means remainder)')]) -> Page[Function]:
    """List all functions in the database (paginated)"""
    return list_functions_real(offset, count)

@mcp.tool()
def list_strings(offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of strings to list (100 is a good default, 0 means remainder)')]) -> Page[String]:
    """List all strings in the database (paginated)"""
    return list_strings_real(offset, count)

@mcp.tool()
def search_strings(pattern: Annotated[str, Field(description='Substring to search for in strings')], offset: Annotated[int, Field(description='Offset to start listing from (start at 0)')], count: Annotated[int, Field(description='Number of strings to list (100 is a good default, 0 means remainder)')]) -> Page[String]:
    """Search for strings containing the given pattern (case-insensitive)"""
    return search_strings_real(pattern, offset, count)

@mcp.tool()
def decompile_function(address: Annotated[str, Field(description='Address of the function to decompile')]) -> str:
    """Decompile a function at the given address"""
    return decompile_function_real(address)

@mcp.tool()
def disassemble_function(start_address: Annotated[str, Field(description='Address of the function to disassemble')]) -> str:
    """Get assembly code (address: instruction; comment) for a function"""
    return disassemble_function_real(start_address)

@mcp.tool()
def get_xrefs_to(address: Annotated[str, Field(description='Address to get cross references to')]) -> list[Xref]:
    """Get all cross references to the given address"""
    return get_xrefs_to_real(address)

@mcp.tool()
def get_entry_points() -> list[Function]:
    """Get all entry points in the database"""
    return get_entry_points_real()

@mcp.tool()
def set_comment(address: Annotated[str, Field(description='Address in the function to set the comment for')], comment: Annotated[str, Field(description='Comment text')]) -> str:
    """Set a comment for a given address in the function disassembly and pseudocode"""
    return set_comment_real(address, comment)

@mcp.tool()
def rename_local_variable(function_address: Annotated[str, Field(description='Address of the function containing the variable')], old_name: Annotated[str, Field(description='Current name of the variable')], new_name: Annotated[str, Field(description='New name for the variable (empty for a default name)')]) -> str:
    """Rename a local variable in a function"""
    return rename_local_variable_real(function_address, old_name, new_name)

@mcp.tool()
def set_local_variable_type(function_address: Annotated[str, Field(description='Address of the function containing the variable')], variable_name: Annotated[str, Field(description='Name of the variable')], new_type: Annotated[str, Field(description='New type for the variable')]):
    """Set a local variable's type"""
    return set_local_variable_type_real(function_address, variable_name, new_type)

@mcp.tool()
def rename_global_variable(old_name: Annotated[str, Field(description='Current name of the global variable')], new_name: Annotated[str, Field(description='New name for the global variable (empty for a default name)')]):
    """Rename a global variable"""
    return rename_global_variable_real(old_name, new_name)

@mcp.tool()
def set_global_variable_type(variable_name: Annotated[str, Field(description='Name of the global variable')], new_type: Annotated[str, Field(description='New type for the variable')]):
    """Set a global variable's type"""
    return set_global_variable_type_real(variable_name, new_type)

@mcp.tool()
def rename_function(function_address: Annotated[str, Field(description='Address of the function to rename')], new_name: Annotated[str, Field(description='New name for the function (empty for a default name)')]):
    """Rename a function"""
    return rename_function_real(function_address, new_name)

@mcp.tool()
def set_function_prototype(function_address: Annotated[str, Field(description='Address of the function')], prototype: Annotated[str, Field(description='New function prototype')]) -> str:
    """Set a function's prototype"""
    return set_function_prototype_real(function_address, prototype)

@mcp.tool()
def declare_c_type(c_declaration: Annotated[str, Field(description='C declaration of the type. Examples include: typedef int foo_t; struct bar { int a; bool b; };')]):
    """Create or update a local type from a C declaration"""
    return declare_c_type_real(c_declaration)       

@mcp.tool()
def get_segments() -> List[Dict[str, Any]]:
    """Get all segments information.
    @return: List of segments (start, end, name, class, perm, bitness, align, comb, type, sel, flags)
    """
    return get_segments_real()
@mcp.tool()
def get_instruction_length(address: int) -> int:
    """
    Retrieves the length (in bytes) of the instruction at the specified address.
    Args:
        address: The address of the instruction.
    Returns:
        The length (in bytes) of the instruction.  Returns 0 if the instruction cannot be decoded.
    """
    return get_instruction_length_real(address)
@mcp.tool()
def get_bytes(ea: int, size: int) -> List[int]:
    """Get bytes at specified address.

    Args:
        ea: Effective address to read from
        size: Number of bytes to read
    """
    return get_bytes_real(ea,size)

def startASYNC():
     asyncio.run(mcp.run_sse_async(host="0.0.0.0", port=26868, log_level="debug"))
def start_server():
        server_thread = threading.Thread(target=startASYNC, daemon=True)
        server_thread.start()
class r0Plugmod(ida_idaapi.plugmod_t):
    def run(self, arg):        
        print(">>> r0mcp.run() is invoked ,Server start")
        start_server()         
class r0mcp(ida_idaapi.plugin_t):    
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "r0mcp is SSE MCP Server automate reverse engineer tool."
    help = ""
    wanted_name = "r0mcp"
    wanted_hotkey = "Shift-R"
    def init(self):
        print(">>>r0mcp plugin loaded, use Edit->Plugins->r0mcp to start SSE server")
        return r0Plugmod()
def PLUGIN_ENTRY():
    return r0mcp()