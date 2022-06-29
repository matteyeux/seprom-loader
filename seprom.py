from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView, BinaryReader
from binaryninja.enums import SymbolType, SegmentFlag, Endianness, SectionSemantics
from binaryninja.types import Symbol
import binascii


class SEPROMView(BinaryView):
    name = "SEPROM"
    long_name = "SEPROM"
    load_address = 0x0

    def __init__(self, data):
        self.reader = BinaryReader(data, Endianness.LittleEndian)
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    def init(self):
        self.raw = self.data
        self.binary = self.raw.read(0, len(self.raw))

        self.add_analysis_completion_event(self.on_complete)

        # set base address
        #if  self.data.read(0xc00, 15) in [b'private_build..', b'AppleSEPROM-323']:
        if self.is_64b():
            self.load_address = 0x240000000
            self.arch = Architecture['aarch64']
            self.platform = self.arch.standalone_platform
        else:
            self.load_address = 0x10000000
            self.arch = Architecture['thumb2']
            self.platform = self.arch.standalone_platform

            print("Base address : " + hex(self.load_address))


        self.add_auto_segment(self.load_address, len(self.parent_view), 0, len(self.parent_view), SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_user_section(self.name, self.load_address, len(self.raw), SectionSemantics.ReadOnlyCodeSectionSemantics)
        self.add_entry_point(self.load_address)
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, self.load_address, '_start'))
        self.update_analysis()

        return True

    @classmethod
    def is_valid_for_data(self, data):
        """Check for a specific string.
        To see if it's a SEPROM file."""
        if data.read(0xc00, 15) in [b'private_build..', b'AppleSEPROM-323']:
            return True
        elif data.read(0x800, 12) == b'AppleSEPROM-':
            return True
        else:
            return False

    def on_complete(self):
        if self.is_64b():
            self.find_interesting64()

    def is_64b(self) -> bool:
        if  self.data.read(0xc00, 15) in [b'private_build..', b'AppleSEPROM-323']:
            return True
        else:
            return False

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
                # account for unknown or bad instruction
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

    def set_name_from_func_xref(self, name, addr):
        if addr is None:
            return None
        refs = self.get_code_refs(addr)
        refs_list = list(refs) 
        if refs_list != 0:
            functions = self.get_functions_containing(refs_list[0].address)
            if len(functions) != 0:
                functions[0].name = name
                print(f"[+] {name} @ {hex(functions[0].lowest_address)}")
                return functions[0].lowest_address
        return None

    def define_func_from_bytesignature(self, signature, func_name):
        ptr = self.start
        while ptr < self.end:
            ptr = self.find_next_data(ptr, signature)
            if not ptr:
                break
            # Only finds first occurance of signature - might want to warn if muliple hits...
            func_start = self.get_functions_containing(ptr)[0].lowest_address
            self.define_function_at_address(func_start, func_name)
            return func_start
        return None

    def define_function_at_address(self, address, name):
        if address is None:
            return None
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, address, name))
        print(f"[+] {name} @ {hex(address)}")

    def find_panic(self, boot_check_panic_addr):
        """
        boot_check_panic has only one MLIL_CALL
        which is panic.
        """
        boot_check_panic = self.get_function_at(boot_check_panic_addr)
        if boot_check_panic is None:
            return None
        for block in boot_check_panic.mlil:
            for instruction in block:
                if instruction.operation.name == 'MLIL_CALL':
                    address = instruction.operands[1].constant
                    panic = self.get_function_at(address)
                    panic.name = "_panic"
                    print(f"[+] _panic @ {hex(panic.start)}")
        return panic

    def find_image4_validate_property_callback(self):
        # find egi0 tag
        egi0_tag = self.find_next_constant(self.load_address, 0x424f5244)
        if egi0_tag is None:
            return None
        img4_validate_property_callback = self.get_functions_containing(egi0_tag)[0]
        return img4_validate_property_callback

    def find_save_img4_tag_value(self, target_function):
        for block in target_function.mlil:
            for instruction in block:
                # check for Certificate Production Status (CPRO) tag
                if "0x4350524f" in str(instruction) and instruction.operation.name == "MLIL_CALL":
                    addr = instruction.operands[1].constant
                    function = self.get_function_at(addr)
                    return function

    def find_image4_verify_number_relation(self, target_function):
        for block in target_function.mlil:
            for instruction in block:
                # check for Board ID (BORD) tag
                if "0x424f5244" in str(instruction) and instruction.operation.name == "MLIL_CALL":
                    addr = instruction.operands[1].constant
                    function = self.get_function_at(addr)
                    return function

    def find_interesting64(self):
        self.resolve_byte_sigs("_bzero", "63e47a924200008b")
        self.resolve_byte_sigs("_reload_cache", "1f8708d5")
        self.resolve_byte_sigs("_DERParseInteger", "00010035e80740f9")
        self.resolve_byte_sigs("_verify_pkcs1_sig", "680e0054a11240f9")
        self.resolve_byte_sigs("_DERParseSequence", "e0010035e80740f9")
        self.resolve_byte_sigs("_DERImg4DecodePayload", "330300b4090140f9")
        self.resolve_byte_sigs("_verify_chain_signatures", "? 09 00 b4 68 12 40 f9")
        self.resolve_byte_sigs("_DERImg4DecodeFindInSequence", "6002803dfd7b44a9")
        self.resolve_byte_sigs("_Img4DecodeCopyPayloadDigest", "? ? 02 91 e0 03 15 aa")
        self.resolve_byte_sigs("_DERImg4DecodeFindProperty", "00008052a80a43b2")
        self.resolve_byte_sigs("_DERDecodeSeqContentInit", "090440f90801098b")
        self.resolve_byte_sigs("_DERParseBitString", "080080d25f000039")
        self.resolve_byte_sigs("_DERDecodeSeqNext", "e80300f9280108cb")
        self.resolve_byte_sigs("_DERParseBoolean", "080140391ffd0371")
        self.resolve_byte_sigs("_Img4DecodeInit", "20010035c0c20091")
        self.resolve_byte_sigs("__parse_chain", "5a3d0012773d0012")
        self.resolve_byte_sigs("_memcpy", "6380009163e87b92")
        self.resolve_byte_sigs("_ccn_cmp", "7f0005ebc080809a")
        self.resolve_byte_sigs("_ccn_sub", "840004eb400000b5")
        self.resolve_byte_sigs("_DERDecodeItemPartialBufferGetLength", "090440f93f0900f1")
        self.resolve_byte_sigs("_Img4DecodeEvaluateDictionaryProperties", "e0031f320afd7ed3")
        self.resolve_byte_sigs("_ccdigest_update", "e100005481fe46d3")
        self.resolve_byte_sigs("_ccdigest_init", "f40300aa60220091")
        self.resolve_byte_sigs("_cchmac_init", "692200918a0b8052")
        self.resolve_byte_sigs("_ccn_add", "840000b1400000b5")
        self.resolve_byte_sigs("_cc_muxp", "08c120cb2800088a")
        self.resolve_byte_sigs("_ccn_n", "630400915f0000f1")
        self.resolve_byte_sigs("_DEROiCompare", "a10100b4020540f9")
        self.resolve_byte_sigs("_DERImg4DecodeParseManifestProperties", "8002803da13a0091")
        self.resolve_byte_sigs("__Img4DecodeGetPropertyData", "00008052e81740f9")
        self.resolve_byte_sigs("_DERImg4DecodeProperty", "e80740b9080943b2")
        self.resolve_byte_sigs("_DERImg4Decode", "61030054882640a9")

        boot_check_panic = self.resolve_byte_sigs("_boot_check_panic", "4900c0d20921a8f2")
        if boot_check_panic is not None:
            self.find_panic(boot_check_panic)

        img4decodegetpayload = self.resolve_byte_sigs("_Img4DecodeGetPayload", "0081c93c2000803d")
        image4_load = self.set_name_from_func_xref("_image4_load", img4decodegetpayload)
        self.set_name_from_func_xref("_load_sepos", image4_load)

        write_ktrr_unknown_el1 = self.find_next_text(self.load_address, "s3_4_c15_c2_5")
        self.define_function_at_address(write_ktrr_unknown_el1, "_write_ktrr_unknown_el1")

        read_ctrr_lock = self.find_next_text(self.load_address, "s3_4_c15_c2_2")
        self.define_function_at_address(read_ctrr_lock, "_read_ctrr_lock")

        img4_validate_property_callback = self.find_image4_validate_property_callback()
        if img4_validate_property_callback is not None:
            self.define_function_at_address(img4_validate_property_callback.start, "_img4_validate_property_callback")

            save_img4_tag_value = self.find_save_img4_tag_value(img4_validate_property_callback)
            self.define_function_at_address(save_img4_tag_value.start, "_save_img4_tag_value")

            img4_verify_number_relation = self.find_image4_verify_number_relation(img4_validate_property_callback)
            self.define_function_at_address(img4_verify_number_relation.start, "_image4_verify_number_relation")

        self.binary = b''
