from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView, BinaryReader, AnalysisCompletionEvent
from binaryninja.enums import SymbolType, SegmentFlag, Endianness, SectionSemantics
from binaryninja.types import Symbol
from binaryninja import Settings
import binascii
import json
import struct
import traceback

use_default_loader_settings = True

class SEPROMView(BinaryView):
    name = "SEPROM"
    long_name = "SEPROM"
    load_address = 0x0
    IS_64 = False
    def __init__(self, data):
        self.reader = BinaryReader(data, Endianness.LittleEndian)
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    def init(self):
        self.raw = self.data
        self.binary = self.raw.read(0, len(self.raw))

        self.add_analysis_completion_event(self.on_complete)

        load_settings = self.get_load_settings(self.name)
        if load_settings is None:

            if self.IS_64:
                self.load_address = 0x240000000
                self.arch = Architecture['aarch64']
                self.platform = self.arch.standalone_platform
            else:
                self.load_address = 0x10000000
                self.arch = Architecture['thumb2']
                self.platform = self.arch.standalone_platform

            print("Base address : " + hex(self.load_address))

        else:
            print("Load Settings: ")
            print(load_settings)
            arch = load_settings.get_string("loader.architecture", self)
            self.arch = Architecture[arch]
            self.platform = self.arch.standalone_platform
            self.load_address = int(load_settings.get_string("loader.imageBase", self))

        self.add_auto_segment(self.load_address, len(self.parent_view), 0, len(self.parent_view), SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_user_section(self.name, self.load_address, len(self.raw), SectionSemantics.ReadOnlyCodeSectionSemantics)
        self.add_entry_point(self.load_address)
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.load_address, '_start'))
        self.update_analysis()

        return True

    @classmethod
    def is_valid_for_data(self, data):
        if data.read(0xc00, 21) == b'private_build...(root':
            self.IS_64 = True
            print("[seprom_loader] This is a 64 bits SEPROM")
            return True
        elif data.read(0x800, 12) == b'AppleSEPROM-':
            print("[seprom_loader] This is a 32 bits SEPROM")
            return True
        else:
            pass
        return False

    @classmethod
    def get_load_settings_for_data(self, data):
        load_settings = Settings("mapped_load_settings")
        if use_default_loader_settings:
            load_settings = self.registered_view_type.get_default_load_settings_for_data(data)
            # specify default load settings that can be overridden (from the UI)
            overrides = ["loader.architecture", "loader.platform", "loader.entryPoint", "loader.imageBase",
                         "loader.segments", "loader.sections"]
            for override in overrides:
                if load_settings.contains(override):
                    load_settings.update_property(override, json.dumps({'readOnly': False}))

            # override default setting value
            load_settings.update_property("loader.imageBase", json.dumps({'default': 0}))
            load_settings.update_property("loader.entryPoint", json.dumps({'default': 0}))
        return load_settings

    def on_complete(self, blah):
        self.find_interesting()

    def resolve_byte_sig_pattern(self, identifier):
        pattern = []
        for byte in identifier.split(' '):
            if byte == '?':
                pattern.append(byte)
            elif byte != '':
                pattern.append(int(byte, 16))
        br = BinaryReader(self)
        result = 0
        length = len(pattern) - 1
        for function in self.functions:
            br.seek(function.start)

            while self.get_functions_containing(br.offset + length) != None and function in self.get_functions_containing(br.offset + length):
                found = True
                count = 0
                for entry in pattern:
                    byte = br.read8()
                    count += 1
                    if entry != byte and entry != '?':
                        found = False
                        break

                br.offset -= count

                if found:
                    result = br.offset
                    break

                instruction_length = self.get_instruction_length(br.offset)
                #account for unknown or bad instruction
                if instruction_length == 0:
                    break
                br.offset += instruction_length

            if result != 0:
                break
        if result == 0:
            return None
        else:
            return self.get_functions_containing(result)[0].lowest_address

    def resolve_byte_sigs(self, name, sequence):
        if "?" in sequence:
            addr = self.resolve_byte_sig_pattern(sequence)
            if addr:
                self.define_function_at_address(addr, name)
            else:
                print("[!] Can't find function {}".format(name))
        else:
            try:
                signature = binascii.unhexlify(sequence)
            except binascii.Error:
                print("[!] Bad Signature for {}! Must be hex encoded string, got: {}.".format(name, sequence))
                return None
            addr = self.define_func_from_bytesignature(signature, name)
            if addr  == None:
                print("[!] Can't find function {}".format(name))
        return addr

    def define_func_from_bytesignature(self, signature, func_name):
        ptr = self.start
        while ptr < self.end:
            # Have to convert signature byearray to a string since find_next_data can't handle bytes on stable
            # fixed on dev in: https://github.com/Vector35/binaryninja-api/commit/c18b89e4cabfc28081a7893ccd4cf8956c9a797f
            signature = "".join(chr(x) for x in signature)
            ptr = self.find_next_data(ptr, signature)
            if not ptr:
                break
            # Only finds first occurance of signature - might want to warn if muliple hits...
            func_start = self.get_functions_containing(ptr)[0].lowest_address
            self.define_function_at_address(func_start, func_name)
            return func_start
        return None

    def define_function_at_address(self, address, name):
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, address, name))
        print(f"[+] {name} @ {hex(address)}")

    def find_interesting(self):
        self.resolve_byte_sigs("_bzero", "63e47a924200008b")
        self.resolve_byte_sigs("_reload_cache", "1f8708d5")
        self.resolve_byte_sigs("_DERParseInteger", "00010035e80740f9")
        self.resolve_byte_sigs("_verify_pkcs1_sig", "680e0054a11240f9")
        self.resolve_byte_sigs("_DERParseSequence", "e0010035e80740f9")
        self.resolve_byte_sigs("_DERImg4DecodePayload", "330300b4090140f9")
        self.resolve_byte_sigs("_Img4DecodeGetPayload", "0081c93c2000803d")
        self.resolve_byte_sigs("_verify_chain_signatures", "? 09 00 b4 68 12 40 f9")
        self.resolve_byte_sigs("_DERImg4DecodeFindInSequence", "6002803dfd7b44a9")
        self.resolve_byte_sigs("_Img4DecodeGetPropertyBoolean", "210843b2e0030091")
        self.resolve_byte_sigs("_Img4DecodeCopyPayloadDigest", "? ? 02 91 e0 03 15 aa")
        self.resolve_byte_sigs("_DERImg4DecodeFindProperty", "00008052a80a43b2")
        self.resolve_byte_sigs("_DERDecodeSeqContentInit", "090440f90801098b")
        self.resolve_byte_sigs("_DERParseBitString", "080080d25f000039")
        self.resolve_byte_sigs("_boot_check_panic", "4900c0d20921a8f2")
        self.resolve_byte_sigs("_DERDecodeSeqNext", "e80300f9280108cb")
        self.resolve_byte_sigs("_DERParseBoolean", "080140391ffd0371")
        self.resolve_byte_sigs("_Img4DecodeInit", "20010035c0c20091")
        self.resolve_byte_sigs("__parse_chain", "5a3d0012773d0012")
        self.resolve_byte_sigs("_memcpy", "6380009163e87b92")

        self.binary = b''
