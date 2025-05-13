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

def _resolve_function_ea(function_address_str: str, function_name: str, operation_description: str) -> int:
    """
    Resolves an address from either a string address or a function name.
    One of function_address_str or function_name must be non-empty.
    This EA can then be used with idaapi.get_func() to get the function context.
    """
    if not function_address_str and not function_name:
        raise IDAError(f"For {operation_description}, either function_address or function_name must be provided.")

    resolved_ea = idaapi.BADADDR

    # Prioritize address if provided and valid
    if function_address_str:
        try:
            resolved_ea = parse_address(function_address_str)
        except IDAError as e:
            # If address parsing fails but a name is also provided, we can try the name.
            # If no name is provided, this is a fatal error for the address.
            if not function_name:
                raise IDAError(f"Invalid function_address '{function_address_str}' for {operation_description} and no function_name provided: {e}")
            # resolved_ea remains BADADDR, name lookup will be attempted next
            pass 

    # If address was not provided, or was invalid (and name is available), try to use the name
    if resolved_ea == idaapi.BADADDR and function_name:
        resolved_ea = idaapi.get_name_ea(idaapi.BADADDR, function_name)
        if resolved_ea == idaapi.BADADDR:
            # Try demangled name
            if not DEMANGLED_TO_EA: # Ensure map is populated if empty
                create_demangled_to_ea_map()
            if function_name in DEMANGLED_TO_EA:
                resolved_ea = DEMANGLED_TO_EA[function_name]

    # Final check if an EA was resolved
    if resolved_ea == idaapi.BADADDR:
        error_message_parts = [f"For {operation_description}, failed to resolve address. Input was:"]
        if function_address_str:
            error_message_parts.append(f"  - function_address: '{function_address_str}'")
        if function_name:
            error_message_parts.append(f"  - function_name: '{function_name}'")
        raise IDAError("\n".join(error_message_parts))
            
    return resolved_ea

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
    size: Annotated[int, "Size of the variable in bytes (mandatory)"],
) -> ConvertedNumber:
    """Convert a number (decimal, hexadecimal) to different representations"""
    try:
        value = int(text, 0)
    except ValueError:
        raise IDAError(f"Invalid number: {text}")

    # Size is now mandatory，因为在部分支持MCP的客户端中存在不允许省略可选参数的情况.
    if not isinstance(size, int) or size <= 0:
        raise IDAError(f"Invalid size: {size}. Must be a positive integer greater than 0.")

    # Convert the number to bytes
    try:
        bytes_val = value.to_bytes(size, "little", signed=True) # Renamed 'bytes' to 'bytes_val' to avoid conflict with built-in
    except OverflowError:
        raise IDAError(f"Number {text} is too big for {size} bytes")

    # Convert the bytes to ASCII
    ascii_str = "" # Renamed 'ascii' to 'ascii_str'
    for byte_char in bytes_val.rstrip(b"\x00"):
        if byte_char >= 32 and byte_char <= 126:
            ascii_str += chr(byte_char)
        else:
            ascii_str = None
            break

    return {
        "decimal": str(value),
        "hexadecimal": hex(value),
        "bytes": bytes_val.hex(" "),
        "ascii": ascii_str,
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
def search_strings_regex_real(
        pattern_str: Annotated[str, "The regular expression to match (case-insensitive)"],
        offset: Annotated[int, "Offset to start listing from (start at 0)"],
        count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
) -> Page[String]:
    """Search for strings that satisfy a regular expression."""
    strings = get_strings()
    try:
        # 如果需要不区分大小写，应使用 re.IGNORECASE 标志)
        pattern = re.compile(pattern_str, re.IGNORECASE)
    except re.error as e:
        raise IDAError(f"Invalid regular expression syntax: {e}")
    try:
        matched_strings = [s for s in strings if s["string"] and re.search(pattern, s["string"])]
    except Exception as e:
        raise IDAError(f"Regular expression matching failed: {e}")
    return paginate(matched_strings, offset, count)

@idaread
def search_strings_substring_real(
    pattern: Annotated[str, "Substring to search for in strings"],
    offset: Annotated[int, "Offset to start listing from (start at 0)"],
    count: Annotated[int, "Number of strings to list (100 is a good default, 0 means remainder)"],
) -> Page[String]:
    """Search for strings containing the given pattern (case-insensitive)."""
    strings = get_strings()
    # 执行不区分大小写的子字符串搜索
    matched_strings = [s for s in strings if s["string"] and pattern.lower() in s["string"].lower()]
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
    address: Annotated[str, "Address of the function to decompile. Can be empty if function_name is provided."],
    function_name: Annotated[str, "Name of the function to decompile. Can be empty if address is provided."]
) -> str:
    """Decompile a function at the given address or by its name"""
    
    resolved_ea = _resolve_function_ea(address, function_name, "decompiling function")
    
    cfunc = decompile_checked(resolved_ea) # decompile_checked takes an integer EA
    
    if is_window_active():
        ida_hexrays.open_pseudocode(cfunc.entry_ea, ida_hexrays.OPF_REUSE) 
        
    sv = cfunc.get_pseudocode()
    pseudocode = ""
    func_object_for_bounds = idaapi.get_func(cfunc.entry_ea) # For address plausibility checks

    for i, sl in enumerate(sv):
        sl: ida_kernwin.simpleline_t
        item = ida_hexrays.ctree_item_t() # Must be created for each call to get_line_item
        
        current_line_addr = idaapi.BADADDR # Default for the line

        # Attempt to get address from ctree_item associated with the line
        if cfunc.get_line_item(sl.line, 0, False, None, item, None):
            # Primary source: item.it.ea
            if item.it and item.it.ea != idaapi.BADADDR:
                current_line_addr = item.it.ea
            else: 
                # Fallback: try parsing item.dstr() if item.it.ea is not valid
                # item.dstr() is available on ctree_item_t
                ds = item.dstr().split(": ")
                if len(ds) == 2:
                    try:
                        parsed_addr_from_dstr = int(ds[0], 16)
                        # Plausibility check: address should be within the function's bounds
                        if func_object_for_bounds and \
                           func_object_for_bounds.start_ea <= parsed_addr_from_dstr < func_object_for_bounds.end_ea:
                            current_line_addr = parsed_addr_from_dstr
                    except ValueError:
                        pass # Not a hex address prefix in dstr

        # Special handling for the very first line:
        # If decompilation was for the function's entry point, and no more specific
        # address was found for the first line itself, use the function's entry_ea.
        if i == 0 and resolved_ea == cfunc.entry_ea and current_line_addr == idaapi.BADADDR:
            current_line_addr = cfunc.entry_ea
        
        line_text = ida_lines.tag_remove(sl.line)
        if len(pseudocode) > 0:
            pseudocode += "\n"
        
        if current_line_addr != idaapi.BADADDR:
            pseudocode += f"/* line: {i}, address: {hex(current_line_addr)} */ {line_text}"
        else:
            pseudocode += f"/* line: {i} */ {line_text}"
            
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

@idawrite
def set_comment_real(
    address: Annotated[str, "Address in the function to set the comment for"],
    comment: Annotated[str, "Comment text"]
) -> str:
    """
    Set a comment for a given address in the function disassembly and pseudocode.
    Returns a string indicating whether the comment was set successfully.
    """
    address = parse_address(address)

    # Set disassembly comment
    if not idaapi.set_cmt(address, comment, False):
        raise IDAError(f"Failed to set disassembly comment at {hex(address)}")
    else:
        print(f"Disassembly comment set successfully at {hex(address)}")

    # Reference: <url id="d0g71o3djm8p5liq0650" type="url" status="parsed" title="Using IDA Python to analyze Trickbot" wc="14166">https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/</url> 
    # Check if the address corresponds to a line
    cfunc = decompile_checked(address)

    # Special case for function entry comments
    if address == cfunc.entry_ea:
        idc.set_func_cmt(address, comment, True)
        cfunc.refresh_func_ctext()
        return "Comment set successfully for function entry"

    eamap = cfunc.get_eamap()
    if address not in eamap:
        print(f"Failed to set decompiler comment at {hex(address)}")
        return "Failed to set decompiler comment"
    
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
            return "Comment set successfully"
        cfunc.del_orphan_cmts()
        cfunc.save_user_cmts()
    print(f"Failed to set decompiler comment at {hex(address)}")
    return "Failed to set decompiler comment"

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
    function_address: Annotated[str, "Address of the function containing the variable. Can be empty if function_name is provided."],
    function_name: Annotated[str, "Name of the function containing the variable. Can be empty if function_address is provided."],
    old_name: Annotated[str, "Current name of the variable"],
    new_name: Annotated[str, "New name for the variable (empty for a default name)"]
) -> str:
    """Rename a local variable in a function with name conflict checking"""
    
    resolved_ea = _resolve_function_ea(function_address, function_name, "renaming local variable")
    func = idaapi.get_func(resolved_ea)
    if not func:
        input_spec = f"address '{function_address}'" if function_address else ""
        if function_name:
            if input_spec: input_spec += " or "
            input_spec += f"name '{function_name}'"
        return f"Error: No function found for {input_spec} (resolved to {hex(resolved_ea)})"
    
    func_ea = func.start_ea # Use the actual start EA of the function

    # Check if new_name is empty (will use default name)
    if not new_name:
        if not ida_hexrays.rename_lvar(func_ea, old_name, ""): # Pass empty string for new_name
            return f"Error: Failed to rename local variable '{old_name}' to default name in function {hex(func_ea)}"
        refresh_decompiler_ctext(func_ea)
        return f"Success: Local variable '{old_name}' renamed to default name in function {hex(func_ea)}"
    
    # Get decompilation of the function
    cfunc = ida_hexrays.decompile(func_ea)
    if not cfunc:
        return f"Error: Failed to decompile function at {hex(func_ea)}"
    
    # Check for name conflicts
    lvars = cfunc.get_lvars()
    for lvar in lvars:
        if lvar.name == new_name and lvar.name != old_name:
            return f"Error: Variable name '{new_name}' already exists in function {hex(func_ea)}"
    
    # Perform the rename
    if not ida_hexrays.rename_lvar(func_ea, old_name, new_name):
        return f"Error: Failed to rename local variable '{old_name}' to '{new_name}' in function {hex(func_ea)}"
    
    refresh_decompiler_ctext(func_ea)
    return f"Success: Local variable '{old_name}' renamed to '{new_name}' in function {hex(func_ea)}"

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
    function_address: Annotated[str, "Address of the function containing the variable. Can be empty if function_name is provided."],
    function_name: Annotated[str, "Name of the function containing the variable. Can be empty if function_address is provided."],
    variable_name: Annotated[str, "Name of the variable"],
    new_type: Annotated[str, "New type for the variable"]
) -> str:
    """Set a local variable's type"""
    
    resolved_ea = _resolve_function_ea(function_address, function_name, "setting local variable type")
    func = idaapi.get_func(resolved_ea)
    if not func:
        input_spec = f"address '{function_address}'" if function_address else ""
        if function_name:
            if input_spec: input_spec += " or "
            input_spec += f"name '{function_name}'"
        raise IDAError(f"No function found for {input_spec} (resolved to {hex(resolved_ea)})")

    func_ea = func.start_ea # Use the actual start EA of the function

    # Parse the new type
    try:
        new_tif = ida_typeinf.tinfo_t()
        # parse_decl requires semicolon for the type
        if ida_typeinf.parse_decl(new_tif, None, new_type+";", ida_typeinf.PT_SIL) is None:
             # Fallback for older IDA versions or simpler types if parse_decl fails subtly
            try:
                new_tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
                if not new_tif.is_valid(): # Check if tinfo_t constructor worked
                    raise IDAError(f"Failed to parse type (constructor): {new_type}")
            except Exception as e_constr:
                 raise IDAError(f"Failed to parse type with parse_decl and constructor: {new_type}. Details: {e_constr}")
    except Exception as e_parse:
        raise IDAError(f"Failed to parse type: {new_type}. Details: {e_parse}")    
    
    # Rename (this is needed to find the variable by ensuring it's in user lvars)
    # Using the same name effectively "touches" the variable for Hex-Rays.
    if not ida_hexrays.rename_lvar(func_ea, variable_name, variable_name):
        # This might fail if the variable doesn't exist or isn't recognized by Hex-Rays yet.
        # Attempting to decompile first might help Hex-Rays recognize it.
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            raise IDAError(f"Failed to decompile function at {hex(func_ea)} to find local variable: {variable_name}")
        if not ida_hexrays.rename_lvar(func_ea, variable_name, variable_name):
             raise IDAError(f"Failed to find or prime local variable for type change: {variable_name} in function {hex(func_ea)}")
    
    # Apply the type change
    modifier = my_modifier_t(variable_name, new_tif)
    if not ida_hexrays.modify_user_lvars(func_ea, modifier):
        raise IDAError(f"Failed to modify local variable type: {variable_name} in function {hex(func_ea)}")    
    
    refresh_decompiler_ctext(func_ea)    
    return (f"Successfully changed type of variable '{variable_name}' "
            f"in function at {hex(func_ea)} "
            f"to '{new_type}'")

@idawrite
def rename_global_variable_real(
    old_name: Annotated[str, "Current name of the global variable"],
    new_name: Annotated[str, "New name for the global variable (empty for a default name)"]
) -> str:
    """Rename a global variable"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)
    if not idaapi.set_name(ea, new_name):
        raise IDAError(f"Failed to rename global variable {old_name} to {new_name}")
    refresh_decompiler_ctext(ea)
    return f"Success: global variable '{old_name}' renamed to '{new_name}' in function {hex(ea)}"
@idawrite
def set_global_variable_type_real(
    variable_name: Annotated[str, "Name of the global variable"],
    new_type: Annotated[str, "New type for the variable"]
) -> str:
    """Set a global variable's type"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    tif = ida_typeinf.tinfo_t(new_type, None, ida_typeinf.PT_SIL)
    if not tif:
        raise IDAError(f"Parsed declaration is not a variable type")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL):
        raise IDAError(f"Failed to apply type")
    return (f"Successfully changed type of variable '{variable_name}' "
            f"in function at {hex(ea)} "
            f"to '{new_type}'")

@idawrite
def rename_function_real(
    function_address: Annotated[str, "Address of the function to rename. Can be empty if function_name is provided."],
    function_name: Annotated[str, "Name of the function to rename. Can be empty if function_address is provided."],
    new_name: Annotated[str, "New name for the function (empty for a default name)"]
) -> str:
    """Rename a function with name conflict checking."""
    
    resolved_ea = _resolve_function_ea(function_address, function_name, "renaming function")
    func = idaapi.get_func(resolved_ea)
    if not func:
        input_spec = f"address '{function_address}'" if function_address else ""
        if function_name:
            if input_spec: input_spec += " or "
            input_spec += f"name '{function_name}'"
        raise IDAError(f"No function found for {input_spec} (resolved to {hex(resolved_ea)}).")
    
    current_func_ea = func.start_ea # Use the actual start EA of the function
    old_name = idaapi.get_name(current_func_ea)

    if new_name and new_name != old_name:
        existing_ea = idaapi.get_name_ea(idaapi.BADADDR, new_name)
        
        if existing_ea != idaapi.BADADDR and existing_ea != current_func_ea:
            conflicting_item_type = "a global symbol"
            conflicting_item_name = idaapi.get_name(existing_ea) 
            if idaapi.get_func(existing_ea):
                conflicting_item_type = f"function '{conflicting_item_name}'"
            
            return (f"Error: Name '{new_name}' is already used by {conflicting_item_type} "
                    f"at {hex(existing_ea)}.")

    if not idaapi.set_name(current_func_ea, new_name if new_name else "", idaapi.SN_CHECK): # SN_CHECK for safety, though set_name implies it
        # If new_name is empty, IDA assigns a default. set_name should handle this.
        # The SN_CHECK flag here is more about validating the name's characters/format if new_name is not empty.
        # idaapi.set_name returns 0 on failure, 1 on success.
        # If new_name is empty, set_name will attempt to give it a default name (e.g. sub_XXXX)
        if not idaapi.set_name(current_func_ea, new_name if new_name else ""):
             raise IDAError(f"Failed to rename function {hex(current_func_ea)} from '{old_name}' to '{new_name or 'default name'}'. "
                       "This could be due to invalid characters in the new name or other IDA restrictions.")
    
    refresh_decompiler_ctext(current_func_ea)
    
    actual_new_name = idaapi.get_name(current_func_ea)
    return f"Successfully renamed function from '{old_name}' to '{actual_new_name}' at {hex(current_func_ea)}"
    
@idawrite
def set_function_prototype_real(
    function_address: Annotated[str, "Address of the function. Can be empty if function_name is provided."],
    function_name: Annotated[str, "Name of the function. Can be empty if function_address is provided."],
    prototype: Annotated[str, "New function prototype"]
) -> str:
    """Set a function's prototype"""
    resolved_ea = _resolve_function_ea(function_address, function_name, "setting function prototype")
    func = idaapi.get_func(resolved_ea)
    if not func:
        input_spec = f"address '{function_address}'" if function_address else ""
        if function_name:
            if input_spec: input_spec += " or "
            input_spec += f"name '{function_name}'"
        raise IDAError(f"No function found for {input_spec} (resolved to {hex(resolved_ea)})")

    func_ea = func.start_ea # Use the actual start EA of the function

    try:
        # Attempt to parse the declaration
        tif = ida_typeinf.tinfo_t()
        # PT_SIL: silent mode, PT_NDC: no decl, PT_TYP: type, PT_VAR: variable, PT_FUN: function
        # We expect a function prototype, so PT_FUN might be relevant for parsing context,
        # but apply_tinfo will verify if it's a function type.
        # parse_decl is generally preferred for complex declarations.
        # It expects a full declaration, often ending with a semicolon.
        parsed_decl = prototype
        if not parsed_decl.strip().endswith(';'):
            # Heuristic: if it looks like a function prototype without a name, e.g. "int (int, char *)"
            # we might need to give it a dummy name for parse_decl.
            # However, apply_tinfo can often handle prototypes directly.
            # For simplicity, let's try with apply_tinfo first, which uses parse_user_type_decl.
            pass

        # Using ida_typeinf.apply_tinfo directly as it internally calls parse_user_type_decl
        # which is more robust for user-provided type strings.
        # ida_typeinf.apply_tinfo will create a tinfo_t internally.
        # We need to ensure the prototype string is correctly formatted for it.
        # A common way is `ida_typeinf.parse_decl(tif, None, prototype + ";", ida_typeinf.PT_SIL)`
        # and then `ida_typeinf.apply_tinfo(func_ea, tif, ida_typeinf.PT_SIL)`

        temp_tif = ida_typeinf.tinfo_t()
        # Add a semicolon if not present, as parse_decl often expects it.
        prototype_to_parse = prototype.strip()
        if not prototype_to_parse.endswith(";"):
            prototype_to_parse += ";"
        
        if ida_typeinf.parse_decl(temp_tif, None, prototype_to_parse, ida_typeinf.PT_SIL) is None:
            raise IDAError(f"Failed to parse prototype string: '{prototype}'. parse_decl returned None.")

        if not temp_tif.is_func():
            raise IDAError(f"Parsed declaration '{prototype}' is not a function type.")
        
        if not ida_typeinf.apply_tinfo(func_ea, temp_tif, ida_typeinf.PT_SIL):
            raise IDAError(f"Failed to apply type information for prototype '{prototype}' to function at {hex(func_ea)}.")
        
        refresh_decompiler_ctext(func_ea)
        return f"Successfully set prototype for function at {hex(func_ea)} to '{prototype}'"

    except Exception as e:
        # Catch any other exceptions during parsing or applying
        raise IDAError(f"Failed to set function prototype '{prototype}' at {hex(func_ea) if func else resolved_ea}: {str(e)}")

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


# 这些函数迟早要重排一遍顺序，使使用场景接近的函数接近，这样在提交给LLM的待续写文本中它们也会相近
# --- START OF REVISED @mcp.tool FUNCTIONS ---
@mcp.tool()
def check_connection() -> str:
    """Checks the connection status with the IDA Pro MCP server and retrieves the loaded module name."""
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
def get_project_metadata() -> Metadata:
    """Retrieves metadata about the currently IDA-Pro project."""
    return get_metadata_real()

@mcp.tool()
def get_function_info_by_name(name: Annotated[str, Field(description='Mangled or demangled name of the target function.')]) -> Function:
    """Retrieves details (address, name, size) for a function using its name (mangled or demangled)."""
    return get_function_by_name_real(name)

@mcp.tool()
def get_function_info_by_address(address: Annotated[str, Field(description="A hexadecimal string start as '0x' (e.g., '0x14001000'), representation of the function's start address.")]) -> Function:
    """Retrieves info (address, name, size) for a function using its starting address."""
    return get_function_by_address_real(address)

@mcp.tool()
def get_current_address() -> str:
    """Gets the address currently selected (under the cursor) in the IDA user interface."""
    return get_current_address_real()

@mcp.tool()
def get_current_function() -> Optional[Function]:
    """Gets details (address, name, size) of the function containing the currently selected in IDA window."""
    return get_current_function_real()

@mcp.tool()
def convert_number(
    text: Annotated[str, Field(description='Number represented as a string (e.g., "100", "0x64"). Supports decimal and hexadecimal formats.')],
    size: Annotated[int, Field(description='Mandatory size in bytes (positive integer) to assume for byte/ASCII conversion.')]
) -> ConvertedNumber:
    """Converts a number string (hex/dec) into various representations: decimal, hexadecimal, bytes (hex), potential ASCII, and binary."""
    return convert_number_real(text, size)

@mcp.tool()
def list_functions(
    offset: Annotated[int, Field(description='Starting index for pagination (0-based).')],
    count: Annotated[int, Field(description='Maximum number of function entries per page (0 retrieves all remaining functions from the offset).')]
) -> Page[Function]:
    """Lists functions defined in the analysis database, with support for pagination."""
    return list_functions_real(offset, count)

@mcp.tool()
def list_strings(
    offset: Annotated[int, Field(description='Starting index for pagination (0-based).')],
    count: Annotated[int, Field(description='Similar to the list_functions method.')]
) -> Page[String]:
    """Lists string literals found in the analysis database, with support for pagination."""
    return list_strings_real(offset, count)

@mcp.tool()
def search_strings_regex(
    pattern_str: Annotated[str, Field(description='Regular expression pattern to match against string literal content (case-insensitive).')],
    offset: Annotated[int, Field(description='Starting index for pagination (0-based).')],
    count: Annotated[int, Field(description='Maximum number of matching string literal entries per page (0 retrieves all remaining matches from the offset).')]
) -> Page[String]:
    """Searches for string literals matching a given regular expression (case-insensitive), returning results paginated."""
    return search_strings_regex_real(pattern_str, offset, count)

@mcp.tool()
def search_strings_substring(
    pattern: Annotated[str, Field(description='Substring to search for within string literal content (case-insensitive).')],
    offset: Annotated[int, Field(description='Similar to the search_strings_regex method.')],
    count: Annotated[int, Field(description='Similar to the search_strings_regex method.')]
) -> Page[String]:
    """Searches for string literals containing a given substring (case-insensitive), returning results paginated."""
    return search_strings_substring_real(pattern, offset, count)

@mcp.tool()
def decompile_function(
    function_address: Annotated[str, Field(description="The function's start address, a hexadecimal string start as '0x' (e.g., '0x14001000'), if not empty string, function_name must be empty string(\"\").")],
    function_name: Annotated[str, Field(description="The name of the function to decompile, if not empty string, function_address must be empty string(\"\").")]
) -> str:
    """Decompiles the function specified by function_address or function_name."""
    return decompile_function_real(function_address, function_name)

@mcp.tool()
def disassemble_function(start_address: Annotated[str, Field(description="The function's start address, a hexadecimal string start as '0x'.")]) -> str:
    """Retrieves the disassembly listing for a function, specified by its start address."""
    return disassemble_function_real(start_address)

@mcp.tool()
def get_xrefs_to(address: Annotated[str, Field(description="The target address, a hexadecimal string start as '0x'.")]) -> list[Xref]:
    """Finds all code and data cross-references (Xrefs) that point *to* the given address."""
    return get_xrefs_to_real(address)

@mcp.tool()
def get_entry_points() -> list[Function]:
    """Lists all defined program entry point functions in the analysis database."""
    return get_entry_points_real()

@mcp.tool()
def set_comment(
    address: Annotated[str, Field(description="Where the comment should be placed, a hexadecimal string start as '0x' (e.g., '0x14001000').")],
    comment: Annotated[str, Field(description='The comment text.')]
) -> str:
    """Sets or updates a comment at a specific address. For line comments, the line address is presented in the decompiled code."""
    return set_comment_real(address, comment)

@mcp.tool()
def rename_local_variable(
    function_address: Annotated[str, Field(description="A hexadecimal string start as '0x', if not empty string, function_name must be empty string(\"\").")],
    function_name: Annotated[str, Field(description='The name of the function containing the local variable, if not empty string, function_address must be empty string("").')],
    old_name: Annotated[str, Field(description='The current name of the local variable as seen in the decompilation.')],
    new_name: Annotated[str, Field(description='The desired new name for the local variable. If empty, IDA assigns a default name.')]
) -> str:
    """Renames a local variable in a function. Identified by function_address or function_name."""
    return rename_local_variable_real(function_address, function_name, old_name, new_name)

@mcp.tool()
def set_local_variable_type(
    function_address: Annotated[str, Field(description="A hexadecimal string start as'0x'.")],
    function_name: Annotated[str, Field(description="The name of the function containing the local variable.")],
    variable_name: Annotated[str, Field(description='The name of the local variable.')],
    new_type: Annotated[str, Field(description='The new C-style data type declaration string (e.g., "int", "char *", "MyStruct *").')]
) -> str:
    """Sets the data type of a local variable in the function. Identified by function_address or function_name, if provid one, the other one must be empty string("")."""
    return set_local_variable_type_real(function_address, function_name, variable_name, new_type)

@mcp.tool()
def rename_global_variable(
    old_name: Annotated[str, Field(description='The current name of the global variable or function.')],
    new_name: Annotated[str, Field(description='The desired new name.')]
) -> str:
    """Renames a global variable (data location) or function identified by its current name."""
    return rename_global_variable_real(old_name, new_name)

@mcp.tool()
def set_global_variable_type(
    variable_name: Annotated[str, Field(description='The name of the global variable whose type needs to be changed.')],
    new_type: Annotated[str, Field(description='The new C-style data type declaration string (e.g., "int", "MyStruct *", "char[16]").')]
) -> str:
    """Sets the data type of a global variable identified by its name."""
    return set_global_variable_type_real(variable_name, new_type)

@mcp.tool()
def rename_function(
    function_address: Annotated[str, Field(description="A hexadecimal string start as'0x' (e.g., '0x14001000'), if not empty string, function_name must be empty string(\"\").")],
    function_name: Annotated[str, Field(description="The name of the function to rename, if not empty string, function_address must be empty string(\"\")")],
    new_name: Annotated[str, Field(description='The desired new name for the function. If empty, IDA assigns a default name.')]
) -> str:
    """Renames the function. Identified by function_address or function_name."""
    return rename_function_real(function_address, function_name, new_name)
    
@mcp.tool()
def set_function_prototype(
    function_address: Annotated[str, Field(description="A hexadecimal string start as'0x'.")],
    function_name: Annotated[str, Field(description="The name of the function whose prototype will be set.")],
    prototype: Annotated[str, Field(description='The new C-style function prototype string (e.g., "int __cdecl my_func(int a, char *b)", "void setup(void)").')]
) -> str:
    """Sets the C-style function prototype for the function. Identified by function_address or function_name, if provid one, the other one must be empty string."""
    return set_function_prototype_real(function_address, function_name, prototype)

@mcp.tool()
def declare_c_type(
    c_declaration: Annotated[str, Field(description='A C language declaration string defining a struct, union, enum, or typedef (e.g., "typedef int user_id_t;", "struct Point { int x; int y; };").')]
):
    """Declares or updates a local type (struct, union, enum, typedef) within IDA's type system using a C declaration string."""
    return declare_c_type_real(c_declaration)

@mcp.tool()
def get_segments() -> List[Dict[str, Any]]:
    """Retrieves information about all memory segments defined in the analysis database (e.g., .text, .data)."""
    return get_segments_real()

@mcp.tool()
def get_machine_instruction_length(address: Annotated[str, Field(description="Address of the machine instruction (e.g., '0x14001000').")]) -> int:
    """Gets the length (in bytes) of the machine instruction located at the given address."""
    parsed_address = parse_address(address)
    return get_instruction_length_real(parsed_address)

@mcp.tool()
@idaread
def get_bytes(
    address: Annotated[str, Field(description="Address to start reading bytes from.")],
    size: Annotated[int, Field(description="The number of bytes to read.")]
) -> List[int]:
    """Reads a sequence of byte values from the specified address. Returns a list of integers (0-255)."""
    parsed_ea = parse_address(address)
    try:
        result = [ida_bytes.get_byte(parsed_ea + i) for i in range(size)]
        return result
    except Exception as e:
        print(f"Error in get_bytes: {str(e)}")
        raise IDAError(f"Failed to read bytes at {hex(parsed_ea)}: {str(e)}") from e

# --- END OF REVISED @mcp.tool FUNCTIONS ---

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
