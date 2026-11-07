"""The tested P102 loop with memory-only status and bounded rollback state."""
import os
import time
import p102


def watch(identity,bdf,publish,stop):
    root=p102.parent_bdf(identity)
    io=p102.Transport(True,True)
    x=None
    try:
        x=p102.Experiment(io,bdf,root,identity['InstanceId'],p102.boot_id())
        result=x.apply()
        publish(phase='running',**result)
        last_status=last_fix=last_trigger=-100
        low_since=None
        while not stop.is_set():
            time.sleep(.02)
            x.valid_root()
            ep,rp=x.link(x.bdf,x.cap),x.link(x.root,x.rcap)
            now=time.monotonic()
            if now-last_status>=1:
                publish(phase='running',endpoint=ep,root=rp)
                last_status=now
            cfg=x.reg(0x8C040)
            x.version=(io.read(x.bdf,x.cap)>>16)&15
            declared=x.version>=2 and io.read(x.bdf,x.cap+0x2C)&6==6
            if now-last_fix>=.2:
                if not declared:
                    for off,mask,value,_ in p102.RECIPE: x.rmw(off,mask,value)
                    last_fix=now
                elif cfg&0xC0000!=0x40000:
                    x.rmw(0x8C040,0xC0000,0x40000); last_fix=now
            if ep['gen']==rp['gen']==2 and ep['width']==rp['width']==4:
                low_since=None; continue
            if low_since is None: low_since=now
            if now-low_since>30: raise RuntimeError('连续 30 秒未能恢复 Gen2，已停止保持。')
            if ep['training'] or rp['training']: continue
            if now-last_trigger>=.02:
                if x.version>=2: x.cfg(False,0x30,15,2)
                x.cfg(True,0x30,15,2)
                x.cfg(True,0x10,32,32,trigger=True)
                last_trigger=now
        publish(phase='stopped')
    except Exception as error:
        message=str(error)
        if x and x.state['writes']:
            try: x.restore()
            except Exception: message+='；无法完整恢复，请停止实验并断电检查。'
        publish(phase='error',message=message)
        raise
    finally: io.close()
