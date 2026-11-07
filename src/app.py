"""P102 Gen2 minimal single-file app. Runtime status lives only in memory."""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
import p102
import policy
import engine
import ipc

VERSION='0.4.3'
ROOT=Path(os.environ.get('ProgramData',r'C:\ProgramData'))/'P102Gen2'
INSTALL=Path(os.environ.get('ProgramFiles',r'C:\Program Files'))/'P102Gen2'
EXE=INSTALL/('P102Gen2-'+VERSION+'.exe')
BUNDLE=Path(getattr(sys,'_MEIPASS',Path(__file__).parent))
TASK='P102 PCIe Gen2'
p102.HERE=policy.HERE=ROOT


def read(path,default=None):
    try: return json.loads(Path(path).read_text(encoding='utf8'))
    except (OSError,ValueError): return default


def run(args,raw=False):
    result=subprocess.run(args,capture_output=True,creationflags=0x08000000)
    if result.returncode:
        import locale
        raise RuntimeError((result.stdout+result.stderr).decode(locale.getpreferredencoding(False),errors='replace').strip())
    if raw: return result.stdout
    if result.stdout.startswith((b'\xff\xfe',b'\xfe\xff')): return result.stdout.decode('utf-16')
    return result.stdout.decode('utf8',errors='replace')


def selected(config=None):
    devices=p102.inventory()
    matches=[d for d in devices if d['InstanceId'].upper().startswith('PCI\\VEN_10DE&DEV_1B07&')]
    if config and config.get('instance'): matches=[d for d in matches if d['InstanceId']==config['instance']]
    if len(matches)!=1: raise RuntimeError('未找到指定 P102，已拒绝操作其他显卡。')
    d=matches[0]
    bdf='%02X:%02X.%X'%(d['Bus'],d['Address']>>16,d['Address']&65535)
    p102.target_device(devices,bdf)
    return d,bdf


def process_alive(pid):
    k=ipc.dll()
    k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD]; k.OpenProcess.restype=C.c_void_p
    k.GetExitCodeProcess.argtypes=[C.c_void_p,C.POINTER(W.DWORD)]
    handle=k.OpenProcess(0x1000,False,int(pid))
    if not handle: return False
    code=W.DWORD()
    try: return bool(k.GetExitCodeProcess(handle,C.byref(code))) and code.value==259
    finally: k.CloseHandle(handle)


def active(state):
    # SYSTEM workers cannot always be inspected from a normal desktop token.
    # The protected writer's fresh shared-memory heartbeat is the authority.
    return state.get('phase') in ('starting','running') and 0<=time.time()-state.get('time',0)<5


def secure_state():
    p102.admin()
    ROOT.mkdir(parents=True,exist_ok=True)
    run(['icacls.exe',str(ROOT),'/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F',
         '*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)RX','/C'])
    (ROOT/'drivers').mkdir(exist_ok=True)
    for name,digest in p102.DRIVERS.items():
        source=BUNDLE/'drivers'/name
        if hashlib.sha256(source.read_bytes()).hexdigest()!=digest: raise RuntimeError('内置驱动校验失败。')
        destination=ROOT/'drivers'/name
        if not destination.exists() or hashlib.sha256(destination.read_bytes()).hexdigest()!=digest:
            shutil.copyfile(source,destination)


def provision():
    secure_state()
    config=read(ROOT/'config.json',{})
    d,bdf=selected(config)
    config.update(instance=d['InstanceId'],bdf=bdf,version=VERSION)
    source=Path(sys.executable).resolve()
    p102.save(ROOT/'config.json',config)
    INSTALL.mkdir(parents=True,exist_ok=True)
    if getattr(sys,'frozen',False) and source!=EXE.resolve():
        if not EXE.exists() or hashlib.sha256(source.read_bytes()).digest()!=hashlib.sha256(EXE.read_bytes()).digest():
            shutil.copyfile(source,EXE)
    return config


def current():
    try:
        channel=ipc.Channel(ipc.STATUS)
        try: return channel.read()
        finally: channel.close()
    except OSError: return {}


def worker():
    lock=ipc.WorkerLock()
    try:
        if not lock.acquired: return 0
        return _worker()
    finally: lock.close()


def _worker():
    p102.admin()
    existing=current()
    if active(existing) and existing.get('pid')!=os.getpid(): return 0
    channel=ipc.Channel(ipc.STATUS,create=True)
    stop=ipc.StopEvent(create=True)
    base=dict(pid=os.getpid(),version=VERSION)
    def publish(**value): channel.write(dict(base,time=time.time(),**value))
    try:
        publish(phase='starting')
        secure_state()
        config=read(ROOT/'config.json',{})
        until=time.monotonic()+120
        while True:
            try:
                device,bdf=selected(config)
                if device['Problem']!=0: raise RuntimeError('P102 未启用或尚未就绪。')
                break
            except Exception:
                if time.monotonic()>until: raise
                time.sleep(3)
        base['bdf']=bdf
        sys.argv=['policy','set','--bdf',bdf]; policy.main()
        _,address=p102.target_device([device],bdf)
        engine.watch(device,address,publish,stop)
        return 0
    except Exception as error:
        publish(phase='error',message=str(error)); return 2
    finally:
        stop.close(); channel.close()


def launch():
    config=provision()
    state=current()
    if active(state): return '保持已运行。'
    subprocess.Popen([str(EXE),'--worker'],creationflags=0x08000000,close_fds=True)
    return '正在启动。'


def task_xml(executable):
    ET.register_namespace('','http://schemas.microsoft.com/windows/2004/02/mit/task')
    ns='{http://schemas.microsoft.com/windows/2004/02/mit/task}'
    def add(parent,name,text=None,**attrs):
        node=ET.SubElement(parent,ns+name,attrs)
        if text is not None: node.text=text
        return node
    root=ET.Element(ns+'Task',version='1.4')
    triggers=add(root,'Triggers'); boot=add(triggers,'BootTrigger')
    add(boot,'Enabled','true'); add(boot,'Delay','PT30S')
    principal=add(add(root,'Principals'),'Principal',id='System')
    for name,value in [('UserId','S-1-5-18'),('RunLevel','HighestAvailable')]: add(principal,name,value)
    settings=add(root,'Settings')
    for name,value in [('MultipleInstancesPolicy','IgnoreNew'),('DisallowStartIfOnBatteries','false'),
                       ('StopIfGoingOnBatteries','false'),('AllowHardTerminate','false'),('StartWhenAvailable','true'),
                       ('Enabled','true'),('ExecutionTimeLimit','PT0S')]: add(settings,name,value)
    restart=add(settings,'RestartOnFailure'); add(restart,'Interval','PT1M'); add(restart,'Count','3')
    execute=add(add(root,'Actions',Context='System'),'Exec')
    add(execute,'Command',str(executable)); add(execute,'Arguments','--worker')
    return ET.tostring(root,encoding='unicode')


def task_details():
    # schtasks can emit bytes that contradict its XML encoding declaration.
    # Query structured task data through our explicit UTF-8 PowerShell bridge.
    code="$t=Get-ScheduledTask -TaskName 'P102 PCIe Gen2' -ErrorAction Stop; "
    code+="$u=[string]$t.Principal.UserId; if($u -notmatch '^S-1-') {$u=([Security.Principal.NTAccount]$u).Translate([Security.Principal.SecurityIdentifier]).Value}; "
    code+="[pscustomobject]@{command=[string]$t.Actions[0].Execute;arguments=[string]$t.Actions[0].Arguments;user=$u;delay=[string]$t.Triggers[0].Delay} | ConvertTo-Json"
    return json.loads(p102.ps(code))


def startup(enable):
    if enable:
        provision()
        xml=ROOT/'startup.xml'; xml.write_text(task_xml(EXE),encoding='utf-16')
        run(['schtasks.exe','/Create','/TN',TASK,'/XML',str(xml),'/F'])
        actual=task_details()
        if (Path(actual['command']).resolve()!=EXE.resolve() or actual['arguments']!='--worker'
                or actual['user']!='S-1-5-18' or actual['delay']!='PT30S'):
            raise RuntimeError('自启任务校验失败。')
    else:
        p102.admin()
        query=subprocess.run(['schtasks.exe','/Query','/TN',TASK],capture_output=True,creationflags=0x08000000)
        if query.returncode==0: run(['schtasks.exe','/Delete','/TN',TASK,'/F'])
        query=subprocess.run(['schtasks.exe','/Query','/TN',TASK],capture_output=True,creationflags=0x08000000)
        if query.returncode==0: raise RuntimeError('未能关闭自启。')
    ROOT.mkdir(parents=True,exist_ok=True)
    p102.save(ROOT/'startup.json',dict(enabled=enable))
    return '已开启自启。' if enable else '已关闭自启。'


def stop():
    p102.admin()
    try:
        event=ipc.StopEvent(); event.set(); event.close()
    except OSError:
        return '保持未运行。'
    return '已停止保持。'


class ExecuteInfo(C.Structure):
    _fields_=[('cbSize',W.DWORD),('fMask',W.ULONG),('hwnd',C.c_void_p),('lpVerb',W.LPCWSTR),
              ('lpFile',W.LPCWSTR),('lpParameters',W.LPCWSTR),('lpDirectory',W.LPCWSTR),
              ('nShow',C.c_int),('hInstApp',C.c_void_p),('lpIDList',C.c_void_p),('lpClass',W.LPCWSTR),
              ('hkeyClass',C.c_void_p),('dwHotKey',W.DWORD),('hIcon',C.c_void_p),('hProcess',C.c_void_p)]


def elevate(action,request):
    info=ExecuteInfo(); info.cbSize=C.sizeof(info); info.fMask=0x40
    info.lpVerb='runas'; info.lpFile=sys.executable
    info.lpParameters=subprocess.list2cmdline(['--action',action,'--request',request]); info.nShow=0
    shell=C.WinDLL('shell32',use_last_error=True)
    shell.ShellExecuteExW.argtypes=[C.POINTER(ExecuteInfo)]; shell.ShellExecuteExW.restype=W.BOOL
    if not shell.ShellExecuteExW(C.byref(info)):
        if C.get_last_error()==1223: raise RuntimeError('已取消授权。')
        raise C.WinError(C.get_last_error())
    if info.hProcess: ipc.dll().CloseHandle(info.hProcess)


def ui():
    import tkinter as tk
    from tkinter import ttk
    window=tk.Tk(); window.title('P102 PCIe 2.0'); window.geometry('380x210'); window.resizable(False,False)
    ttk.Style(window).theme_use('vista')
    frame=ttk.Frame(window,padding=16); frame.pack(fill='both',expand=True)
    title=tk.StringVar(value='未运行'); message=tk.StringVar(value='')
    ttk.Label(frame,textvariable=title,font=('Microsoft YaHei UI',17,'bold')).pack(anchor='w')
    ttk.Label(frame,text='P102-100 · 10DE:1B07',font=('Microsoft YaHei UI',9)).pack(anchor='w',pady=(3,12))
    result=ipc.Channel(ipc.ACTION,create=True,public_write=True)
    status=None; pending=None; minimize=False
    enabled=read(ROOT/'startup.json',{}).get('enabled',False)
    auto=tk.BooleanVar(value=enabled)
    def action(name):
        nonlocal pending,minimize
        if pending:
            auto.set(enabled); return
        token=uuid.uuid4().hex
        try:
            elevate(name,token); pending=(token,name); minimize=name=='start'; message.set('处理中…')
        except Exception as error: auto.set(enabled); message.set(str(error))
    row=ttk.Frame(frame); row.pack(fill='x')
    ttk.Button(row,text='启动',command=lambda:action('start')).pack(side='left',padx=(0,8))
    ttk.Button(row,text='停止',command=lambda:action('stop')).pack(side='left')
    ttk.Checkbutton(frame,text='开机自启',variable=auto,
                    command=lambda:action('startup-on' if auto.get() else 'startup-off')).pack(anchor='w',pady=(10,3))
    ttk.Label(frame,textvariable=message,wraplength=345,font=('Microsoft YaHei UI',8)).pack(anchor='w')
    def refresh():
        nonlocal status,pending,enabled,minimize
        if status is None:
            try: status=ipc.Channel(ipc.STATUS)
            except OSError: pass
        state=status.read() if status else {}
        if state.get('phase')=='error': title.set('已停止'); message.set(state.get('message','操作失败。'))
        elif active(state):
            if state.get('phase')=='starting': title.set('启动中…')
            else:
                ep,rp=state.get('endpoint',{}),state.get('root',{})
                ready=ep.get('gen')==rp.get('gen')==2 and ep.get('width')==rp.get('width')==4
                title.set('PCIe 2.0 ×4 · 运行中' if ready else '恢复 Gen2 中…')
                if minimize and ready: window.iconify(); minimize=False
        else: title.set('未运行')
        reply=result.read()
        if pending and reply.get('request')==pending[0]:
            message.set(reply.get('message',''))
            if pending[1].startswith('startup') and reply.get('ok'): enabled=pending[1]=='startup-on'
            auto.set(enabled); pending=None
            if not reply.get('ok'): minimize=False
        window.after(1000,refresh)
    def close():
        result.close()
        if status: status.close()
        window.destroy()
    window.protocol('WM_DELETE_WINDOW',close)
    window.after(100,refresh); window.mainloop()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--action',choices=['start','stop','startup-on','startup-off'])
    parser.add_argument('--request',default='')
    parser.add_argument('--self-test',type=Path)
    args=parser.parse_args()
    if args.self_test:
        import tkinter
        result=dict(version=VERSION,frozen=bool(getattr(sys,'frozen',False)),runtime_status='shared-memory',runtime_disk_writes=False,
                    drivers={n:hashlib.sha256((BUNDLE/'drivers'/n).read_bytes()).hexdigest()==h for n,h in p102.DRIVERS.items()},
                    target=hex(p102.DEVICE),tk=tkinter.Tcl().eval('info patchlevel'))
        p102.save(args.self_test,result); return 0
    if args.worker:
        try: return worker()
        except Exception: return 2
    if args.action:
        result=None
        try:
            result=ipc.Channel(ipc.ACTION,create=True,public_write=True)
            p102.admin()
            if args.action=='start': message=launch()
            elif args.action=='stop': message=stop()
            else: message=startup(args.action=='startup-on')
            result.write(dict(request=args.request,ok=True,message=message)); return 0
        except Exception as error:
            if result: result.write(dict(request=args.request,ok=False,message=str(error)))
            return 2
        finally:
            if result: result.close()
    ui(); return 0


if __name__=='__main__':
    if sys.stdout is None: sys.stdout=open(os.devnull,'w')
    if sys.stderr is None: sys.stderr=open(os.devnull,'w')
    raise SystemExit(main())
