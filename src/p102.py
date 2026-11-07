"""P102 Gen2 Lab: experimental GP102 recipe, Windows x64, Python 3.10+.
Independent implementation. Protocol/recipe references: see RESEARCH.md.
No hardware access occurs on import. No firmware, fuse, or PCI-ID writes.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
DEVICE = 0x1B0710DE
RECIPE = [
    (0x8872C, 0xF, 6, 'XVE speed/width override'),
    (0x2241C, 0x81, 0x81, 'PTOP live capability gates'),
    (0x8841C, 0x6000, 0, 'clear Gen2 disable fields'),
    (0x8C2C0, 4, 0, 'PL CYA0'),
    (0x8C300, 0x10, 0, 'PL CYA1'),
    (0x8C040, 0xC0000, 0x40000, 'Pascal speed request 5 GT/s'),
    (0x8C1C0, 0xF0000, 0x20000, 'link rate Gen2'),
    (0x88610, 0x1001, 1, 'VSEC hierarchy'),
]
MASKS = {offset: mask for offset, mask, _, _ in RECIPE}
DRIVERS = {
    'WinRing0x64.sys': '11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5',
    'ThrottleStop.sys': '16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0',
}


def ps(script):
    p = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                       capture_output=True, encoding='utf-8', errors='replace',creationflags=0x08000000)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip())
    return p.stdout.strip().lstrip('\ufeff')


def inventory():
    return json.loads(ps("[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "
        "$ErrorActionPreference='Stop'; $a=@(Get-PnpDevice -PresentOnly -Class Display | ForEach-Object { "
        "$d=$_; $p=@{}; Get-PnpDeviceProperty -InstanceId $d.InstanceId | ForEach-Object {$p[$_.KeyName]=$_.Data}; "
        "[pscustomobject]@{Name=$d.FriendlyName;InstanceId=$d.InstanceId;Status=[string]$d.Status;"
        "Problem=$p['DEVPKEY_Device_ProblemCode'];Bus=$p['DEVPKEY_Device_BusNumber'];"
        "Address=$p['DEVPKEY_Device_Address'];Parent=$p['DEVPKEY_Device_Parent'];"
        "Speed=$p['DEVPKEY_PciDevice_CurrentLinkSpeed'];Width=$p['DEVPKEY_PciDevice_CurrentLinkWidth'];"
        "Driver=$p['DEVPKEY_Device_Driver']}}); ConvertTo-Json -InputObject $a -Depth 4"))


def target_device(devices, bdf):
    m = re.fullmatch(r'([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-7])', bdf)
    if not m:
        raise RuntimeError('BDF must be hexadecimal BB:DD.F, e.g. 0F:00.0')
    bus, dev, fn = (int(x, 16) for x in m.groups())
    matches = [d for d in devices if re.match(r'PCI\\VEN_10DE&DEV_1B07&', d['InstanceId'], re.I)
               and d['Bus'] == bus and d['Address'] == ((dev << 16) | fn)]
    if len(matches) != 1:
        raise RuntimeError('Exact P102 identity and BDF not found; refusing fallback to another GPU')
    return matches[0], (bus, dev, fn)


def admin():
    if not C.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('Administrator terminal required; no automatic elevation')


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    for attempt in range(50):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt==49: raise
            time.sleep(.1)  # Windows readers may temporarily omit FILE_SHARE_DELETE


def boot_id():
    return ps("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')")


class DriverIOError(RuntimeError):
    def __init__(self, code, error):
        self.error = error & 0xFFFFFFFF
        super().__init__('IOCTL failed: 0x%X, Windows error 0x%X' % (code,self.error))


class Transport:
    """Explicitly loads two hash-pinned upstream driver binaries on request.
    Only DWORD PCI reads, WORD PCI writes and bounded target BAR0 mappings.
    Never borrows another tool's driver services or handles.
    """
    def __init__(self, load=False, reuse_owned=False):
        self.owned = []
        self.handles = []
        self.pages = {}
        self.k = C.WinDLL('kernel32', use_last_error=True)
        self.k.CreateFileW.argtypes = [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, C.c_void_p]
        self.k.CreateFileW.restype = C.c_void_p
        self.k.CloseHandle.argtypes = [C.c_void_p]
        self.k.DeviceIoControl.argtypes = [C.c_void_p,W.DWORD,C.c_void_p,W.DWORD,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.c_void_p]
        self.k.DeviceIoControl.restype = W.BOOL
        self.k.CreateMutexW.argtypes = [C.c_void_p, W.BOOL, W.LPCWSTR]
        self.k.CreateMutexW.restype = C.c_void_p
        self.mutex = self.k.CreateMutexW(None, False, 'Global\\P102Gen2Lab')
        self.k.WaitForSingleObject.argtypes = [C.c_void_p, W.DWORD]
        self.k.ReleaseMutex.argtypes = [C.c_void_p]
        if not self.mutex or self.k.WaitForSingleObject(self.mutex, 0) not in (0, 0x80):
            if self.mutex: self.k.CloseHandle(self.mutex)
            self.mutex = None
            raise RuntimeError('Another P102 Lab instance is active')
        try:
            if not load:
                raise RuntimeError('Register access requires --load-drivers (installs temporary kernel services)')
            for file, expected in DRIVERS.items():
                path = HERE / 'drivers' / file
                if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise RuntimeError('Missing/incorrect driver: ' + file + '; run prepare-drivers.ps1')
            for svc, file, device in [('P102LabWr','WinRing0x64.sys',r'\\.\WinRing0_1_2_0'),
                                      ('P102LabTs','ThrottleStop.sys',r'\\.\P102LabTs')]:
                expected=DRIVERS[file]
                q = self.sc('query', svc)
                if q.returncode != 1060:
                    if not reuse_owned or q.returncode:
                        raise RuntimeError('Service already exists or cannot be queried: ' + svc)
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,'SYSTEM\\CurrentControlSet\\Services\\'+svc) as key:
                        image=winreg.QueryValueEx(key,'ImagePath')[0]
                    image=os.path.expandvars(image).strip('"')
                    slash=chr(92)
                    if image.lstrip(slash).startswith('??'+slash):
                        image=image.lstrip(slash)[2:].lstrip(slash)
                    image=os.path.normpath(image)
                    if Path(image).resolve()!= (HERE/'drivers'/file).resolve():
                        if not Path(image).is_file() or hashlib.sha256(Path(image).read_bytes()).hexdigest()!=expected:
                            raise RuntimeError('Existing driver image hash differs; refusing reuse')
                else:
                    p = self.sc('create', svc, 'type=', 'kernel', 'start=', 'demand', 'binPath=', str(HERE/'drivers'/file))
                    if p.returncode: raise RuntimeError(p.stdout + p.stderr)
                    self.owned.append(svc)
                    p = self.sc('start', svc)
                    if p.returncode: raise RuntimeError('Driver load rejected: '+p.stdout+p.stderr)
                h = self.k.CreateFileW(device, 0xC0000000, 0, None, 3, 0, None)
                if h in (None, C.c_void_p(-1).value):
                    raise RuntimeError('Cannot open exclusive driver handle: '+device+'; Windows error '+str(C.get_last_error()))
                self.handles.append(h)
            self.wr, self.ts = self.handles
        except BaseException:
            self.close()
            raise

    @staticmethod
    def sc(*args):
        return subprocess.run(['sc.exe', *args], capture_output=True, text=True, errors='replace',creationflags=0x08000000)

    def ioctl(self, handle, code, data, size):
        ib = C.create_string_buffer(data)
        ob = C.create_string_buffer(size)
        n = W.DWORD()
        if not self.k.DeviceIoControl(handle, code, ib, len(data), ob, size, C.byref(n), None):
            raise DriverIOError(code,C.get_last_error())
        if n.value < size:
            raise RuntimeError('Short driver response')
        return ob.raw

    def read(self, bdf, offset):
        import struct
        b,d,f = bdf
        try:
            raw = self.ioctl(self.wr, 0x9C406144, struct.pack('<II',(b<<8)|(d<<3)|f,offset & ~3),4)
        except DriverIOError as error:
            if offset == 0 and error.error == 0xE0000002:  # OLS_ERROR_PCI_NO_DEVICE
                return 0xFFFFFFFF
            raise
        return int.from_bytes(raw, 'little')

    def word(self, bdf, offset):
        return (self.read(bdf,offset) >> ((offset & 2)*8)) & 0xFFFF

    def write_word(self, bdf, offset, value):
        # WinRing0 PCI write accepts a variable payload length. WORD avoids
        # writing W1C status bits in the neighboring upper half of a DWORD.
        import struct
        data = struct.pack('<IIH', (bdf[0]<<8)|(bdf[1]<<3)|bdf[2], offset, value)
        ib = C.create_string_buffer(data)
        n = W.DWORD()
        if not self.k.DeviceIoControl(self.wr,0x9C40A148,ib,len(data),None,0,C.byref(n),None):
            raise RuntimeError('PCI WORD write failed')

    def mmio(self, bar, offset, value=None):
        import struct
        if offset not in MASKS:
            raise RuntimeError('Non-whitelisted BAR offset')
        page = bar + (offset & ~4095)
        if page not in self.pages:
            raw = self.ioctl(self.ts,0x8000645C,struct.pack('<QI',page,4096),8)
            address = int.from_bytes(raw,'little')
            if not address: raise RuntimeError('Null BAR mapping')
            self.pages[page] = address
        cell = C.c_uint32.from_address(self.pages[page] + (offset & 4095))
        if value is not None: cell.value = value
        return cell.value

    def close(self):
        for h in self.handles: self.k.CloseHandle(h)
        self.handles.clear()
        for svc in reversed(self.owned):
            stopped = self.sc('stop',svc)
            deleted = self.sc('delete',svc)
            if stopped.returncode not in (0,1062) or deleted.returncode:
                print('Cleanup warning for '+svc, file=sys.stderr)
        self.owned.clear()
        if self.mutex:
            self.k.ReleaseMutex(self.mutex)
            self.k.CloseHandle(self.mutex)
            self.mutex = None


def capability(io, bdf):
    ptr = io.read(bdf,0x34) & 0xFC
    seen = set()
    while 0x40 <= ptr <= 0xFC and ptr not in seen:
        seen.add(ptr)
        value = io.read(bdf,ptr)
        if value & 0xFF == 0x10:
            if (value >> 16) & 0xF < 1: raise RuntimeError('Invalid PCIe capability version')
            return ptr
        ptr = (value >> 8) & 0xFC
    raise RuntimeError('No valid PCIe capability')


class Experiment:
    def __init__(self, io, bdf, root, identity, boot):
        self.io, self.bdf, self.root = io,bdf,root
        self.alive()
        self.rootid = io.read(root,0)
        if self.rootid in (0,0xFFFFFFFF) or io.read(root,8) >> 16 != 0x0604:
            raise RuntimeError('Parent is not a PCI bridge')
        buses = io.read(root,0x18)
        if ((buses >> 8) & 0xFF) != bdf[0]:
            raise RuntimeError('Parent does not directly own target bus')
        if ((buses >> 16) & 0xFF) != bdf[0]:
            raise RuntimeError('Parent has downstream buses; refusing shared-bridge retrain')
        for dev in range(32):
            for fn in range(8):
                other=(bdf[0],dev,fn)
                if other != bdf and io.read(other,0) not in (0,0xFFFFFFFF):
                    raise RuntimeError('Target bus has another PCI function; refusing shared-bus retrain')
        self.cap, self.rcap = capability(io,bdf),capability(io,root)
        self.version=(io.read(bdf,self.cap)>>16)&15
        self.rversion=(io.read(root,self.rcap)>>16)&15
        barraw = io.read(bdf,0x10)
        if barraw & 7: raise RuntimeError('Expected non-prefetchable 32-bit BAR0')
        self.bar = barraw & 0xFFFFFFF0
        if not self.bar or self.bar == 0xFFFFFFF0: raise RuntimeError('Invalid BAR0')
        if not io.word(bdf,4) & 2: raise RuntimeError('Memory decode disabled; enable P102 first')
        self.state = dict(schema=1,device=DEVICE,bdf=bdf,root=root,rootid=self.rootid,bar=self.bar,
                          instance=identity,boot=boot,created=dt.datetime.now(dt.timezone.utc).isoformat(),writes=[])

    def alive(self):
        for _ in range(3):
            if self.io.read(self.bdf,0) != DEVICE:
                raise RuntimeError('P102 identity lost/mismatched; stop. Cold power-off may be required')

    def valid_root(self):
        self.alive()
        if self.io.read(self.root,0) != self.rootid:
            raise RuntimeError('Upstream identity changed')

    def reg(self, offset):
        self.alive()
        value = self.io.mmio(self.bar,offset)
        if value == 0xFFFFFFFF or value >> 16 == 0xBADF:
            raise RuntimeError('Inaccessible/protected MMIO 0x%X' % offset)
        return value

    def snapshot(self):
        self.valid_root()
        return dict(endpoint=self.link(self.bdf,self.cap),root=self.link(self.root,self.rcap),
                    registers={hex(o):hex(self.reg(o)) for o in MASKS})

    def link(self,bdf,cap):
        status = self.io.word(bdf,cap+0x12)
        version=(self.io.read(bdf,cap)>>16)&15
        return dict(gen=status & 15,width=(status>>4)&63,training=bool(status & 0x800),
                    capability_version=version,
                    lnksta=hex(status),lnkcap=hex(self.io.read(bdf,cap+0xC)),
                    lnkcap2=hex(self.io.read(bdf,cap+0x2C)) if version>=2 else None,
                    tls=self.io.word(bdf,cap+0x30)&15 if version>=2 else None)

    def record(self,kind,offset,mask,old,new,root=False):
        # One original value per field, only in memory. No history or disk I/O.
        for entry in self.state['writes']:
            if (entry['kind'],entry['offset'],entry['root'])==(kind,offset,root):
                entry.update(new=new,status='pending')
                entry.pop('restore',None)
                return entry
        entry=dict(kind=kind,offset=offset,mask=mask,old=old,new=new,root=root,status='pending')
        self.state['writes'].append(entry)
        return entry

    @staticmethod
    def legal_speed(value):
        # Do not touch width-arm bits; reject either invalid quadrant.
        return bool(value & (1<<29)) and not bool(value & (1<<31))

    def rmw(self,offset,mask,value):
        if offset not in MASKS or mask != MASKS[offset]: raise RuntimeError('Bad register/mask')
        old=self.reg(offset)
        new=(old & ~mask) | (value & mask)
        if offset == 0x8C040 and not self.legal_speed(new):
            raise RuntimeError('Unexpected width-arm state; refusing cross-card constant overwrite')
        if old == new: return
        self.alive()
        e=self.record('mmio',offset,mask,old,new)
        self.io.mmio(self.bar,offset,new)
        time.sleep(.02)
        readback=self.reg(offset)
        e.update(readback=readback,status='verified' if (readback & mask)==(new & mask) else 'mismatch')

        if e['status'] != 'verified': raise RuntimeError('Register write did not latch: '+hex(offset))

    def cfg(self,root,offset,mask,value,trigger=False):
        self.valid_root()
        bdf=self.root if root else self.bdf
        cap=self.rcap if root else self.cap
        if (offset,mask) not in ((0x30,15),(0x10,32)) or (trigger and not root):
            raise RuntimeError('PCI write outside TLS/retrain allowlist')
        if offset==0x30 and (self.rversion if root else self.version)<2:
            raise RuntimeError('Never write Link Control 2 in a v1 capability')
        old=self.io.word(bdf,cap+offset)
        new=(old & ~mask)|(value & mask)
        if old==new: return
        e=self.record('cfg',offset,mask,old,new,root)
        self.io.write_word(bdf,cap+offset,new)
        time.sleep(0 if trigger else .02)
        self.valid_root()
        readback=self.io.word(bdf,cap+offset)
        e.update(readback=readback,status='triggered' if trigger else 'verified')

        if not trigger and (readback & mask)!=(new & mask): raise RuntimeError('TLS write clamped')

    def apply(self,seconds=5):
        before=self.snapshot()
        if self.rversion<2: raise RuntimeError('Upstream capability v2 required for target-speed control')
        if int(before['root']['lnkcap'],16)&15 < 2: raise RuntimeError('Parent cannot do Gen2')
        if not self.legal_speed(self.reg(0x8C040)): raise RuntimeError('Unexpected LINK_CONFIG width state')
        self.state.setdefault('baseline',before)

        if before['endpoint']['gen'] >= 2:
            return before  # no downgrade or additional writes
        for off,mask,val,_ in RECIPE: self.rmw(off,mask,val)
        deadline=time.monotonic()+2
        def declares_gen2():
            if self.version>=2: return self.io.read(self.bdf,self.cap+0x2C)&6 == 6
            return self.io.read(self.bdf,self.cap+0xC)&15 >= 2
        while not declares_gen2():
            self.alive()
            if time.monotonic()>deadline: raise RuntimeError('Gen2 capability did not latch')
            time.sleep(.05)
        # On this P102 the live group changes the advertised capability v1->v2.
        self.version=(self.io.read(self.bdf,self.cap)>>16)&15
        if self.version>=2: self.cfg(False,0x30,15,2)
        self.cfg(True,0x30,15,2)
        self.cfg(True,0x10,32,32,trigger=True)
        deadline=time.monotonic()+seconds
        last_retrain=time.monotonic()
        seen=0
        while time.monotonic()<deadline:
            self.valid_root()
            ep,rp=self.link(self.bdf,self.cap),self.link(self.root,self.rcap)
            ok=ep['gen']==rp['gen']==2 and ep['width']==rp['width']==before['endpoint']['width'] and not ep['training'] and not rp['training']
            seen=seen+1 if ok else 0
            if seen>=10:
                result=self.snapshot()
                self.state['result']=result
                self.state['verdict']='GEN2_LINK_OBSERVED_BANDWIDTH_NOT_VERIFIED'

                return result
            if not ok and not ep['training'] and not rp['training']:
                # Driver initialization may rewrite SPEED multiple times during
                # this observation window. Reclaim the source fields instead
                # of blocking for five seconds after a single initial write.
                for off,mask,val,_ in RECIPE: self.rmw(off,mask,val)
                self.version=(self.io.read(self.bdf,self.cap)>>16)&15
                if self.version>=2: self.cfg(False,0x30,15,2)
                self.cfg(True,0x30,15,2)
                if time.monotonic()-last_retrain>=2:
                    self.cfg(True,0x10,32,32,trigger=True)
                    last_retrain=time.monotonic()
            time.sleep(.1)
        raise RuntimeError('No sustained Gen2 on both ends; this GP102 recipe is unverified')

    def restore(self):
        self.valid_root()
        # Restore TLS while the endpoint still advertises v2, before clearing
        # gates that revert this P102 to a v1 capability structure.
        entries=[e for e in reversed(self.state['writes']) if e['kind']=='cfg' and e['offset']==0x30]
        entries += [e for e in reversed(self.state['writes']) if e['kind']=='mmio']
        for e in entries:
            if e.get('restore')=='verified': continue
            self.valid_root()
            if e['kind']=='mmio':
                off,mask=e['offset'],e['mask']
                if off not in MASKS or mask!=MASKS[off]: raise RuntimeError('Invalid rollback register')
                cur=self.reg(off)
                value=(cur & ~mask)|(e['old'] & mask)
                if off==0x8C040 and not self.legal_speed(value): raise RuntimeError('Unsafe rollback width state')
                self.io.mmio(self.bar,off,value)
                rb=self.reg(off)
            else:
                bdf=self.root if e['root'] else self.bdf
                cap=self.rcap if e['root'] else self.cap
                if ((self.io.read(bdf,cap)>>16)&15)<2:
                    e['restore']='absent_v1_control_skipped'; continue
                mask=15
                cur=self.io.word(bdf,cap+0x30)
                value=(cur & ~mask)|(e['old'] & mask)
                self.io.write_word(bdf,cap+0x30,value)
                rb=self.io.word(bdf,cap+0x30)
            if rb & mask != value & mask: raise RuntimeError('Rollback readback mismatch')
            e['restore']='verified'

        self.valid_root()
        cur=self.io.word(self.root,self.rcap+0x10)
        self.io.write_word(self.root,self.rcap+0x10,cur|32)
        self.state['rollback']='controls_restored_link_requires_recheck'



def parent_bdf(d):
    # Resolve the OS-selected immediate parent rather than guessing a bridge.
    script="[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $ErrorActionPreference='Stop'; "
    script+="$p=@{}; Get-PnpDeviceProperty -InstanceId '"+d['Parent'].replace("'","''")+"' | ForEach-Object {$p[$_.KeyName]=$_.Data}; "
    script+="[pscustomobject]@{Bus=$p['DEVPKEY_Device_BusNumber'];Address=$p['DEVPKEY_Device_Address']} | ConvertTo-Json"
    p=json.loads(ps(script))
    return (int(p['Bus']),int(p['Address'])>>16,int(p['Address'])&0xFFFF)

