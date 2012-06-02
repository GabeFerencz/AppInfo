# Gabe Ferencz
# AppInfo - requires win32 extensions for context menu entry

import win32ui as wu
import win32con as wc
import win32clipboard as winclip
import sys

def checksum(bytes):
    return sum((w+1)&0xFFFF for w in words(bytes))

def take(n, src):
    src = iter(src)
    for i in xrange(n):
        yield src.next()

def chunks(size, src, tail=True):
    src = iter(src)
    try:
        while True:
            data = []
            for i in xrange(size):
                data.append(src.next())
            yield data
    except StopIteration:
        if tail and data:
            yield data
        
def words(bytes, little_endian=True):
    if little_endian:
        return (msb<<8|lsb for lsb, msb in chunks(2, bytes))
    else:
        return (msb<<8|lsb for msb, lsb in chunks(2, bytes))

def cs_line(line):
    '''Takes a string and calculates the intel line checksum'''
    bytes = [int(line[2*x:2*x+2],16) for x in range(len(line)/2)]
    line_sum = (((sum(bytes)^0xFF)+1)&0xFF)
    return line_sum

def GetEmbeddedInfo(f):
    from operator import add
    blocks = parse(f, block_size=0x10000)
    # Copy embedded info, which resides in the last 8 bytes
    info = blocks[max(blocks.keys())][-8:]
    [version, revision, pwba_id] = info[:3]
    # Embedded checksum is last 4 bytes, little endian
    e_cksum = info[4] + (info[5]<<8) + (info[6]<<16) + (info[7]<<24)
    # Hack out embedded checksum so calculated checksum is correct
    blocks[max(blocks.keys())][-4:] = [255,255,255,255]
    # Checksum the hacked blocks
    cksum = checksum(take(len(blocks)*0x10000-4, reduce(add, blocks.values())))
    # Check against the embedded checksum
    if cksum != e_cksum:
        str1 = 'Embedded and calculated checksum mismatch:\n\n'
        str2 = '0x%X  embedded.\n'%e_cksum
        str3 = '0x%X  calculated.'%cksum
        ThrowError(str1 + str2 + str3)
    return [version, revision, pwba_id, cksum]

def parse(f, start=0, end=0xFFFFFFFF, block_size=0x10000):
    if isinstance(f, (str, unicode)):
        f = open(f, 'rb')
    base = 0
    blocks = {}
    for i,l in enumerate(f):
        l = l.strip()
        if not l.startswith(":"):
            ThrowError("Bad hex file: bad start-of-record in line %d"%i)
        count = int(l[1:3], 16)
        addr = int(l[3:7], 16)
        rec = int(l[7:9], 16)
        data = [int(l[i:i+2], 16) for i in range(9,9+count*2,2)]
        checksum = int(l[9+count*2:], 16)

        if (count+(addr&0xFF)+((addr>>8)&0xFF)+rec+sum(data)+checksum)&0xFF != 0:
            ThrowError("Bad hex file: checksum failed on line %d"%i)

        if rec == 0:
            a = base+addr
            if a < start or end < a: continue
            while data:
                block_addr = (a//block_size)*block_size
                if block_addr not in blocks:
                    blocks[block_addr] = []
                block = blocks[block_addr]
                offset = a%block_size
                if len(block) < offset:
                    block.extend([255]*(offset-len(block)))
                if offset+count > block_size:
                    block.extend(data[:block_size-offset])
                    count -= block_size-offset
                    a += block_size-offset
                else:
                    block.extend(data)
                    break
        elif rec == 1:
            break
        elif rec == 2:
            assert addr == 0, (i, addr)
            assert count == 2, (i, count)
            assert data[0]&0x0F == 0, (i, data)
            base = (data[0]<<8|data[1])<<4
        elif rec == 3:
            pass
        elif rec == 4:
            assert addr == 0, (i, addr)
            assert count == 2, (i, count)
            base = (data[0]<<8|data[1])<<16
        elif rec == 5:
            pass
        else:
            ThrowError("Bad hex file: Unsupported record {0}".format(rec))#, rec, lines.index(l))
    return blocks

def Install(menu_name='Smart Remote App Info'):
    '''Install registry entry for adding to context menu.'''
    import _winreg as wr, os
    
    q = ("WARNING: You should back up your registry before making changes!" + 
         "\n\nAre you sure you want me to edit your registry now?")
    if WarnDialog(q):
        for ext in ['.hex','.sum']:
            # Check for extension handler override
            try:
                override = wr.QueryValue(wr.HKEY_CLASSES_ROOT, ext)
                if override:
                    ext = override
            except WindowsError:
                pass
            keyVal = ext + '\\Shell\\' + menu_name + '\\command'
            try:
                key = wr.OpenKey(wr.HKEY_CLASSES_ROOT, 
                                        keyVal, 
                                        0, 
                                        wr.KEY_ALL_ACCESS)
            except WindowsError:
                key = wr.CreateKey(wr.HKEY_CLASSES_ROOT, keyVal)
            regEntry = (r'"C:\Python26\pythonw.exe" "' + os.getcwd() + 
                        r'\AppInfo.py" "%1"')
            wr.SetValueEx(key, '', 0, wr.REG_SZ, regEntry)
            wr.CloseKey(key)
    return

def WarnDialog(question, title = 'App Info Install Confirmation Box'):
    '''Simple yes/no dialog box that uses win32 extensions if available.'''
    try:
        import win32ui as wu
        import win32con as wc
        ans = wu.MessageBox(question, title, 
                            (wc.MB_YESNO|wc.MB_ICONWARNING)) == wc.IDYES
    except ImportError:
        ans = raw_input(question).lower() in ['y','yes']
    return ans

def ThrowError(message, title = 'App Info Error'):
    '''Container for error messages to the user.'''
    wu.MessageBox(message, title, (wc.MB_OK|wc.MB_ICONERROR))
    raise Exception(message)
    return
    
def getClipboardText(): 
    winclip.OpenClipboard() 
    d=winclip.GetClipboardData(wc.CF_TEXT) 
    winclip.CloseClipboard() 
    return d 
 
def setClipboardText(aString, aType=wc.CF_TEXT): 
    winclip.OpenClipboard()
    winclip.EmptyClipboard()
    winclip.SetClipboardData(aType,aString) 
    winclip.CloseClipboard()
    
if __name__ == "__main__":    
    if len(sys.argv) == 1:
        Install()
    if len(sys.argv) == 2:
        hex_file = sys.argv[1]
        [version, revision, pwba_id, cksum] = GetEmbeddedInfo(hex_file)
        info_str =  ('App checksum matches calculated checksum.\n\n' + 
                     'Version:   %s.%02d\n'%(version,revision)+
                     'PWBA ID:   %s\n'%pwba_id +
                     'Checksum:  0x%X'%cksum + 
                     '\n\nCopy checksum to clipboard?')
        ans = wu.MessageBox(info_str,'App Info: %s'%hex_file,
                      (wc.MB_YESNO|wc.MB_ICONINFORMATION))
        if ans == wc.IDYES:
            setClipboardText('%X'%cksum)
    

