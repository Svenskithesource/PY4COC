from __future__ import print_function
import os, struct, marshal, zlib, sys, re, json, base64, shutil, colorama, time
from uuid import uuid4 as uniquename
colorama.init(convert=True)

def decompyle(filename):
    os.system(f'pycdc.exe {filename}.pyc > {filename}.py')

# imp is deprecated in Python3 in favour of importlib
if sys.version_info.major == 3:
    from importlib.util import MAGIC_NUMBER
    pyc_magic = MAGIC_NUMBER
else:
    import imp
    pyc_magic = imp.get_magic()


class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path


    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            print('[!] Error: Could not open {0}'.format(self.filePath))
            return False
        return True


    def close(self):
        try:
            self.fPtr.close()
        except:
            pass


    def checkFile(self):
        print('[+] Processing {0}'.format(self.filePath))
        # Check if it is a 2.0 archive
        self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))

        if magicFromFile == self.MAGIC:
            self.pyinstVer = 20     # pyinstaller 2.0
            print('[+] Pyinstaller version: 2.0')
            return True

        # Check for pyinstaller 2.1+ before bailing out
        self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)
        magicFromFile = self.fPtr.read(len(self.MAGIC))

        if magicFromFile == self.MAGIC:
            print('[+] Pyinstaller version: 2.1+')
            self.pyinstVer = 21     # pyinstaller 2.1+
            return True

        print('[!] Error : Unsupported pyinstaller version or not a pyinstaller archive(Not Python)')
        return False


    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.fileSize - self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver) = \
                struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.fileSize - self.PYINST21_COOKIE_SIZE, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver, pylibname) = \
                struct.unpack('!8siiii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))

        except:
            print('[!] Error : The file is not a pyinstaller archive')
            return False

        print('[+] Python version: {0}'.format(self.pyver))

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        print('[+] Length of package: {0} bytes'.format(self.overlaySize))
        return True


    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iiiiBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack( \
                '!iiiBc{0}s'.format(entrySize - nameLen), \
                self.fPtr.read(entrySize - 4))

            name = name.decode('utf-8').rstrip('\0')
            if len(name) == 0:
                name = str(uniquename())
                print('[!] Warning: Found an unamed file in CArchive. Using random name {0}'.format(name))

            self.tocList.append( \
                                CTOCEntry(                      \
                                    self.overlayPos + entryPos, \
                                    cmprsdDataSize,             \
                                    uncmprsdDataSize,           \
                                    cmprsFlag,                  \
                                    typeCmprsData,              \
                                    name                        \
                                ))

            parsedLen += entrySize
        print('[+] Found {0} files in CArchive'.format(len(self.tocList)))


    def _writeRawData(self, filepath, data):
        nm = filepath.replace('\\', os.path.sep).replace('/', os.path.sep).replace('..', '__')
        nmDir = os.path.dirname(nm)
        if nmDir != '' and not os.path.exists(nmDir): # Check if path exists, create if not
            os.makedirs(nmDir)

        with open(nm, 'wb') as f:
            f.write(data)


    def extractFiles(self):
        print('[+] Beginning extraction...please standby')
        extractionDir = os.path.join(os.getcwd(), os.path.basename(self.filePath) + '_extracted')

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize # Sanity Check

            if entry.typeCmprsData == b's':
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                print('[+] Possible entry point: {0}.pyc'.format(entry.name))
                self._writePyc(entry.name + '.pyc', data)
                
                decompyle(entry.name)

            elif entry.typeCmprsData == b'M' or entry.typeCmprsData == b'm':
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header's intact
                self._writeRawData(entry.name + '.pyc', data)

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                    self._extractPyz(entry.name)


    def _writePyc(self, filename, data):
        with open(filename, 'wb') as pycFile:
            pycFile.write(pyc_magic)            # pyc magic

            if self.pyver >= 37:                # PEP 552 -- Deterministic pycs
                pycFile.write(b'\0' * 4)        # Bitfield
                pycFile.write(b'\0' * 8)        # (Timestamp + size) || hash 

            else:
                pycFile.write(b'\0' * 4)      # Timestamp
                if self.pyver >= 33:
                    pycFile.write(b'\0' * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)


    def _extractPyz(self, name):
        dirName =  name + '_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0' # Sanity Check

            pycHeader = f.read(4) # Python magic value

            # Skip PYZ extraction if not running under the same python version
            if pyc_magic != pycHeader:
                print('[!] Warning: This script is running in a different Python version than the one used to build the executable.')
                print('[!] Please run this script in Python{0} to prevent extraction errors during unmarshalling'.format(self.pyver))
                print('[!] Skipping pyz extraction')
                return

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print('[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.'.format(name))
                return

            print('[+] Found {0} files in PYZ archive'.format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode('utf-8')
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace('..', '__').replace('.', os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')

                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[!] Error: Failed to decompress {0}, probably encrypted. Extracting as is.'.format(filePath))
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)


class Deob:
    def __init__(self, filename):
        self.filename = filename
        self.comment_num = 0
        self.plusobf_num = 0
        self.pycobf_num = 0
        self.ox72obf_num = 0
        self.davidobf_num = 0
        self.developmentobf_num = 0

    def deob(self):
        did_deob = [True]
        while True in did_deob:
            did_deob = [self.pycobf(), self.comment(), self.plusobf(), self.ox72obf(), self.developmentobf(),
                        self.print1()]

    def comment(self):
        with open(self.filename, "r") as f:
            lines = [line.rstrip() for line in f.readlines() if line != "\n"]
        for line in lines:
            
            linenum = line.split("#line:")
            if len(linenum) > 2:
                self.comment_num += 1
                break
        else:
            return False

        new_lines = []

        for line in lines:
            tabs = []
            for char in line:
                if char != " ":
                    break
                tabs.append(" ")
            tabs = "".join(tabs)
            correct_code = tabs + line.split("#line:")[-1].split(":", 1)[-1]
            new_lines.append(correct_code + "\n")

        with open(self.filename, "w") as f:
            f.write("".join(new_lines))
        return True

    def developmentobf(self):
        with open(self.filename, "r") as f:
            lines = [line.rstrip() for line in f.readlines() if line != "\n"]


        if "\x6d\x61\x67\x69\x63" in "\n".join(lines):
            print("test")
            self.developmentobf_num += 1
        else:
            return False

        lines = lines[:-1]
        lines.insert(0, "global trust")
        exec("\n".join(lines))
        deobed = base64.b64decode(trust)
        with open(self.filename, "wb") as f:
            f.write(deobed)

        return True


    def plusobf(self):
        with open(self.filename, "r") as f:
            lines = [line.rstrip() for line in f.readlines() if line != "\n"]
        vuln_line = "nope"
        for line in lines:
            if re.match(re.escape("""exec(''.join([chr(len(i)) for i in d]))"""), line):
                vuln_line = line
                self.plusobf_num += 1
                break

        if vuln_line == "nope":
            return False
        regex = re.findall("\[(.*?)\]", "".join(lines))
        lst = "[" + regex[1] + "]"
        lst = json.loads(lst.replace("'", '"'))
        deobed = "".join([chr(len(i)) for i in lst])
        with open(self.filename, "w") as f:
            f.write(deobed)

        return True

    def pycobf(self):
        with open(self.filename, "r", encoding="latin-1") as f:
            line = f.readlines()[0].rstrip()
            if line == "B":
                self.pycobf_num += 1
            else:
                return False

        name = os.path.splitext(self.filename)[0]
        os.rename(self.filename, name + ".pyc")
        os.system('pycdc.exe {0}.pyc > {0}.py'.format(entry.name))
        os.remove(name + ".pyc")
        return True

    def ox72obf(self):
        with open(self.filename, "r") as f:
            lines = [line.rstrip() for line in f.readlines() if line != "\n"]

        protectors = re.findall('_0x72_Protector_.* = .*', "\n".join(lines))

        if protectors:
            self.ox72obf_num += 1
        else:
            return False
        line = protectors[5].split(" = b'")[1].replace(chr(92) * 2, chr(92))[:-1]
        exec(f"global b; b = b'''{line}'''")
        decoded = b.decode("utf-16")
        with open(self.filename, "w") as f:
            f.write(decoded)
        return True

    # def trustobf(self):
    #     with open(self.filename, "r") as f:
    #         lines = [line.rstrip() for line in f.readlines() if line != "\n"]

    #     vuln_line = "nope"
    #     for line in lines:
    #         if r"eval(compile(base64.b64decode(eval(" in line:
    #             vuln_line = line
    #             self.trustobf_num += 1
    #             break

    #     if vuln_line == "nope":
    #         return False

    #     lines.remove(vuln_line)
    #     exec("global trust\n" + "\n".join(lines))
    #     code = base64.b64decode(trust).decode("utf-8")
    #     with open(self.filename, "w") as f:
    #         f.write(code)
    #     return True

    def davidobf(self):
        regex = re.compile("\'(.*?)\'")
        vulture = os.popen("vulture " + self.filename).read().split("\n")
        vulture = [line for line in vulture if line != "\n"]
        codes = regex.findall("".join(vulture))
        with open(self.filename, "r") as f:
            lines = [line.rstrip() for line in f.readlines() if line != "\n"]
        deobed = []
        for line in lines:
            for variable in codes:
                if variable in line:
                    break
            else:
                if codes:
                    deobed.append(line)
        if deobed:
            with open(self.filename, "w") as f:
                f.write("\n".join(deobed))
            self.davidobf_num += 1
            return True
        else:
            return False

    def print1(self):
        os.system("cls")
        logo = """.______   ____    ____  _  _      ______   ______     ______.
|   _  \  \   \  /   / | || |    /      | /  __  \   /      |
|  |_)  |  \   \/   /  | || |_  |  ,----'|  |  |  | |  ,----'               By svenskithesource#2815
|   ___/    \_    _/   |__   _| |  |     |  |  |  | |  |                            &
|  |          |  |        | |   |  `----.|  `--'  | |  `----.                   Cox#4633
| _|          |__|        |_|    \______| \______/   \______|
                                                                     """
        print(colorama.Fore.CYAN + logo)
        print(colorama.Fore.WHITE + f'=======' + colorama.Fore.CYAN + ' Unpacked ' + colorama.Fore.WHITE + '=========\n'
              + colorama.Fore.WHITE + f'[+]' + colorama.Fore.CYAN + f' PYC File: {self.pycobf_num}\n'
              + colorama.Fore.WHITE + f'[+]' + colorama.Fore.CYAN + f' PlusOBF: {self.plusobf_num}\n'
              + colorama.Fore.WHITE + f'[+]' + colorama.Fore.CYAN + f' Comment vulnerability: {self.comment_num}\n'
              + colorama.Fore.WHITE + f'[+]' + colorama.Fore.CYAN + f' 0x72OBF: {self.ox72obf_num}\n'
              + colorama.Fore.WHITE + f'[+]' + colorama.Fore.CYAN + f' DavidOBF: {self.davidobf_num}\n'
              + colorama.Fore.WHITE + f'[+]' + colorama.Fore.CYAN + f' DevelopmentToolsObf: {self.developmentobf_num}\n'
              + colorama.Fore.WHITE + '==========================\n')


def unpack(filename):
    arch = PyInstArchive(filename)
    if arch.open():
        if arch.checkFile():
            if arch.getCArchiveInfo():
                arch.parseTOC()
                arch.extractFiles()
                arch.close()
                print('[+] Successfully Unpacked.')
                return
        arch.close()


def main():
    logo = """.______   ____    ____  _  _      ______   ______     ______.
    |   _  \  \   \  /   / | || |    /      | /  __  \   /      |
    |  |_)  |  \   \/   /  | || |_  |  ,----'|  |  |  | |  ,----'               By svenskithesource#2815
    |   ___/    \_    _/   |__   _| |  |     |  |  |  | |  |                            &
    |  |          |  |        | |   |  `----.|  `--'  | |  `----.                   Cox#4633
    | _|          |__|        |_|    \______| \______/   \______|
                                                                        """
    if len(sys.argv) < 2:
        os.system('cls')
        print(colorama.Fore.CYAN + logo)
        os.system('title PY4COC By 𝘾𝙤𝙭#4633 and svenskithesource#2815')
        print(colorama.Fore.RED + '[+] Usage: PY4COC.py <filename>')
        time.sleep(3)
    else:
        filename = sys.argv[1]
        if filename.endswith(".pyc"):
            decompyle(filename[:-4])
            filename = filename[:-1]
        elif not filename.endswith(".py"):
            os.system('cls')
            print(colorama.Fore.CYAN + logo + colorama.Fore.GREEN)
            os.system('title PY4COC By 𝘾𝙤𝙭#4633 and svenskithesource#2815')
            unpack(filename)
            os.chdir("../")
            #shutil.rmtree(filename + "_extracted")
            filename = os.path.splitext(filename)[0] + ".py"
        Deob(filename).deob()


if __name__ == '__main__':
    main()
