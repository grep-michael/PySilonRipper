#proof of concept, gunna create a golang binary to do the same later
"""
stole alot of code from this guy and the offical pyinstaller repo
https://github.com/extremecoders-re/pyinstxtractor
https://github.com/pyinstaller/pyinstaller/blob/9c83be7455f611c3e05f75ee16b873966d5d2a94/PyInstaller/archive/readers.py#L38

PySilon used pyinstaller 2.1+ by default
"""
from pprint import pprint
import dis
import os
import struct
import marshal
import zlib
import sys
from uuid import uuid4 as uniquename

class SilonRipper():

    CONFIG_MAGIC = b'\x29\x03\x7a\x14' #subject to change
    #optimally we would decompile the pyc into bytecode for more consistant parsing but apparently theres literally zero way to do that

    def __init__(self,path):
        self.path = path
        self.extractor = PycSilonExtractor(path)
        print(path)

    def rip_config(self):
        # we called change directory in extractPySilon so we should already be in the directory with all the files we need
        files = [f for f in os.listdir(".") if os.path.isfile(f)]
        for file in files:
            
            #29037a14
            with open(file, "rb") as pysilonFile:
                
                rawData = pysilonFile.read()
                configStart = rawData.find(self.CONFIG_MAGIC)
                configEnd = rawData.find(b"info")
                print(rawData[configStart:configEnd])
                self._parse_bot_tokens(rawData[configStart:configEnd])

    def _parse_bot_tokens(self,data):
        seperator = b'\x7a\x1c'
        end_tokens = b'\x52\xDA\x11'
        token1 = data[len(self.CONFIG_MAGIC):data.find(seperator)]
        print(token1)

    def extract_pysilon(self):
        self.extractor.check_pyinstaller()
        self.extractor.get_table_of_contents()
        self.extractor.parseTOC()
        self.extractor.extractPySilon()
        self.extractor.close() 

class PycSilonExtractor:

    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b'\0' * 4
        self.open()

    def open(self):
        self.fPtr = open(self.filePath, 'rb')
        self.fileSize = os.stat(self.filePath).st_size

    def close(self):
        self.fPtr.close()

    def check_pyinstaller(self):
        searchChunkSize = 8192
        endPos = self.fileSize
        cookiePos = -1
        MAGIC = b'MEI\014\013\012\013\016'

        
        startPos = endPos - searchChunkSize 
        #chunkSize = endPos - startPos
        #if chunkSize < len(self.MAGIC):
        #    break
        
        self.fPtr.seek(startPos, os.SEEK_SET)
        data = self.fPtr.read(searchChunkSize)
        
        offs = data.rfind(MAGIC)
        
        if offs == -1:
            raise Exception("Not a pyinstaller file me thinks")
            return -1
        self.cookiePos = startPos + offs
        
        print("[!] Pyinstaller detected")

        

        return True

    def get_table_of_contents(self):
        try:
            self.fPtr.seek(self.cookiePos, os.SEEK_SET)

            # Read CArchive cookie
            (magic, lengthofPackage, toc_offset, toc_length, pyver, pylibname) = \
            struct.unpack('!8sIIii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))

        except:
            raise('The file is not a pyinstaller archive')
        #print((magic, lengthofPackage, toc_offset, toc_length, pyver, pylibname))


        self.pymaj, self.pymin = (pyver//100, pyver%100) if pyver >= 100 else (pyver//10, pyver%10)
        print('[+] Python version: {0}.{1}'.format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = self.fileSize - self.cookiePos - self.PYINST21_COOKIE_SIZE

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc_offset
        self.tableOfContentsSize = toc_length

        print('[+] Length of package: {0} bytes'.format(lengthofPackage))
        return True

    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = {}
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iIIIBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack( \
                '!IIIBc{0}s'.format(entrySize - nameLen), \
                self.fPtr.read(entrySize - 4))

            try:
                name = name.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                newName = str(uniquename())
                print('[!] Warning: File name {0} contains invalid bytes. Using random name {1}'.format(name, newName))
                name = newName
            
            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                print('[!] Warning: Found an unamed file in CArchive. Using random name {0}'.format(name))

            self.tocList[name] = {
                'entry_offset':self.overlayPos + entryPos,
                'data_length':cmprsdDataSize,
                'uncompressed_length':uncmprsdDataSize,
                'compression_flag':cmprsFlag,
                'typecode':typeCmprsData
            }
            parsedLen += entrySize
        print('[+] Found {0} files in CArchive'.format(len(self.tocList)))

    def _writePyc(self, filename, data):
        with open(filename, 'wb') as pycFile:
            pycFile.write(self.pycMagic)            # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:                # PEP 552 -- Deterministic pycs
                pycFile.write(b'\0' * 4)        # Bitfield
                pycFile.write(b'\0' * 8)        # (Timestamp + size) || hash 

            else:
                pycFile.write(b'\0' * 4)      # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b'\0' * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)

    def extractPySilon(self):
        print('[+] Beginning extraction...please standby')
        extractionDir = os.path.join(os.getcwd(), os.path.basename(self.filePath) + '_extracted')

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for name in self.tocList:
            entry = self.tocList[name]

            self.fPtr.seek(entry["entry_offset"], os.SEEK_SET)
            data = self.fPtr.read(entry["data_length"])

            if entry["compression_flag"] == 1:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    print('[!] Error : Failed to decompress {0}'.format(entry.name))
                    continue
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry['uncompressed_length'] # Sanity Check

            basePath = os.path.dirname(name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry['typecode'] == b's':
                # s -> ARCHIVE_ITEM_PYSOURCE
                # we search for known strings in the PySilon file

                if data.find(b'wipes the malware off of the victim\'s PC') > 0:
                    print('[+] Possible PySilon found: {0}.pyc'.format(name))
                    self._writePyc(name + '.pyc', data)



def main(args):
    ripper = SilonRipper(args[0])
    ripper.extract_pysilon()
    ripper.rip_config()
if __name__ == "__main__":
    args = ("all_features.exe",)
    main(args)

    #'0x2b4fb'