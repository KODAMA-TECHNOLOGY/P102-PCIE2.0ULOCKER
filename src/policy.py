"""P102-only driver strategy flags used by upstream P104 tool, with backup."""
import argparse
import json
import re
import sys
from p102 import inventory,target_device,admin,save,HERE


def main():
    import winreg as R
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['show','set','restore'])
    p.add_argument('--bdf',required=True)
    a=p.parse_args()
    d,_=target_device(inventory(),a.bdf)
    driver=d['Driver']
    if not re.fullmatch(r'\{4d36e968-e325-11ce-bfc1-08002be10318\}\\[0-9]{4}',driver,re.I): raise RuntimeError('Invalid driver class key')
    key='SYSTEM\\CurrentControlSet\\Control\\Class\\'+driver
    names=['RMPcieLinkSpeed','RmForceEnableGen2','RmEnableGen2']
    backup=HERE/'policy-backup.json'
    values={}
    with R.OpenKey(R.HKEY_LOCAL_MACHINE,key) as k:
        for n in names:
            try:
                value,kind=R.QueryValueEx(k,n)
                if kind!=R.REG_DWORD: raise RuntimeError('Unexpected policy registry type')
                values[n]={'exists':True,'value':value}
            except FileNotFoundError: values[n]={'exists':False}
    if a.command=='show': print(json.dumps(values,indent=2)); return
    admin()
    if a.command=='set':
        if backup.exists():
            old=json.loads(backup.read_text(encoding='utf8'))
            if old['instance']!=d['InstanceId'] or old['key']!=key: raise RuntimeError('Policy backup identity changed')
        else: save(backup,dict(instance=d['InstanceId'],key=key,values=values))
        desired={n:dict(exists=True,value=1) for n in names}
    else:
        old=json.loads(backup.read_text(encoding='utf8'))
        if old['instance']!=d['InstanceId'] or old['key']!=key: raise RuntimeError('Policy backup identity changed')
        desired=old['values']
    with R.OpenKey(R.HKEY_LOCAL_MACHINE,key,0,R.KEY_SET_VALUE|R.KEY_QUERY_VALUE) as k:
        for n in names:
            v=desired[n]
            if v['exists']:
                R.SetValueEx(k,n,0,R.REG_DWORD,v['value'])
                if R.QueryValueEx(k,n)!=(v['value'],R.REG_DWORD): raise RuntimeError('Policy verification failed')
            else:
                try: R.DeleteValue(k,n)
                except FileNotFoundError: pass
                try: R.QueryValueEx(k,n)
                except FileNotFoundError: continue
                raise RuntimeError('Policy deletion verification failed')
    print('P102 driver policy '+a.command+' verified; driver may reread it on next initialization.')


if __name__=='__main__':
    try: main()
    except Exception as e: print('ERROR:',e,file=sys.stderr); sys.exit(2)
