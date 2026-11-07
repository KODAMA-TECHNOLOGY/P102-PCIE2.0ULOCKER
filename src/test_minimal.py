import ast
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid
import tempfile
import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock
import app
import ipc
import p102
from fake_hardware import Fake,EP,RP


class MinimalTests(unittest.TestCase):
    def test_system_worker_status_uses_fresh_heartbeat(self):
        with patch('app.process_alive',return_value=False):
            self.assertTrue(app.active(dict(phase='running',time=app.time.time(),pid=999)))
        self.assertFalse(app.active(dict(phase='running',time=app.time.time()-10,pid=999)))
        self.assertFalse(app.active(dict(phase='stopped',time=app.time.time(),pid=999)))

    def test_memory_status_roundtrip_and_reader_survives_writer(self):
        name='Local\\P102Test'+uuid.uuid4().hex
        writer=ipc.Channel(name,create=True,public_write=True)
        reader=ipc.Channel(name)
        try:
            writer.write({'status':'运行中','gen':2})
            self.assertEqual(reader.read(),{'status':'运行中','gen':2})
            writer.close()
            self.assertEqual(reader.read()['gen'],2)
        finally: writer.close(); reader.close()

    def test_memory_status_can_be_read_by_another_process(self):
        name='Local\\P102Test'+uuid.uuid4().hex
        channel=ipc.Channel(name,create=True,public_write=True)
        try:
            channel.write({'pid':123,'phase':'running'})
            code='import ipc,json; c=ipc.Channel('+repr(name)+'); print(json.dumps(c.read())); c.close()'
            result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,check=True,cwd=Path(__file__).parent)
            self.assertEqual(json.loads(result.stdout)['phase'],'running')
        finally: channel.close()

    def test_gpu_apply_and_restore_do_not_write_any_state_files(self):
        io=Fake(); old=dict(io.regs)
        with patch('p102.save',side_effect=AssertionError('runtime wrote to disk')),patch('p102.time.sleep'):
            operation=p102.Experiment(io,EP,RP,'test-device','boot')
            self.assertEqual(operation.apply()['endpoint']['gen'],2)
            operation.restore()
        self.assertEqual(io.regs,old)

    def test_repeated_writes_keep_one_original_value_in_ram(self):
        io=Fake()
        with patch('p102.time.sleep'):
            operation=p102.Experiment(io,EP,RP,'test-device','boot')
            original=io.regs[0x8C040]
            for _ in range(100):
                io.regs[0x8C040]=original
                operation.rmw(0x8C040,0xC0000,0x40000)
            self.assertEqual(len(operation.state['writes']),1)
            operation.restore()
        self.assertEqual(io.regs[0x8C040],original)

    def test_public_app_has_no_log_or_customer_specific_paths(self):
        text=Path(app.__file__).read_text(encoding='utf8')
        for forbidden in ('worker.log','actions.log','live-status.json','2080','SSL','Documents','legacy_home'):
            self.assertNotIn(forbidden,text)
        self.assertNotIn('save(',Path(__file__).with_name('engine.py').read_text(encoding='utf8'))

    def test_2080_and_other_cards_cannot_be_selected(self):
        with patch('app.p102.inventory',return_value=[dict(InstanceId=r'PCI\VEN_10DE&DEV_1E87&TEST',Bus=14,Address=0)]):
            with self.assertRaises(RuntimeError): app.selected()

    def test_target_bus_is_discovered_from_this_computer(self):
        device=dict(InstanceId=r'PCI\VEN_10DE&DEV_1B07&CLIENT',Bus=42,Address=0)
        with patch('app.p102.inventory',return_value=[device]):
            self.assertEqual(app.selected()[1],'2A:00.0')

    def test_boot_task_is_headless_and_uses_installed_generic_exe(self):
        xml=app.ET.fromstring(app.task_xml(app.EXE))
        self.assertEqual(xml.find('.//{*}UserId').text,'S-1-5-18')
        self.assertEqual(xml.find('.//{*}Arguments').text,'--worker')
        self.assertEqual(xml.find('.//{*}Delay').text,'PT30S')
        self.assertIsNotNone(xml.find('.//{*}BootTrigger'))
        logon=xml.find('.//{*}LogonType')
        if logon is not None:
            self.assertIn(logon.text,('S4U','Password','InteractiveToken','InteractiveTokenOrPassword'))

    def test_task_verification_uses_structured_unicode_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); exe=root/'P102Gen2.exe'
            details=json.dumps(dict(command=str(exe),arguments='--worker',user='S-1-5-18',delay='PT30S'))
            def completed(args,**kwargs):
                return subprocess.CompletedProcess(args,0,b'',b'')
            with patch('app.ROOT',root),patch('app.EXE',exe),patch('app.provision'),patch('app.subprocess.run',side_effect=completed),patch('app.p102.ps',return_value=details),patch('app.p102.save') as saved:
                app.startup(True)
                self.assertTrue(saved.call_args.args[1]['enabled'])

    def test_disabling_startup_does_not_require_gpu_or_provisioning(self):
        with tempfile.TemporaryDirectory() as directory:
            result=subprocess.CompletedProcess([],1,b'',b'not found')
            with patch('app.ROOT',Path(directory)),patch('app.provision',side_effect=AssertionError('must not probe GPU')),patch('app.p102.admin'),patch('app.subprocess.run',return_value=result),patch('app.p102.save') as saved:
                app.startup(False)
                self.assertFalse(saved.call_args.args[1]['enabled'])

    def test_reused_driver_uses_its_own_hash_not_the_previous_loops_hash(self):
        # Exercise constructor reuse with two DIFFERENT hashes and kernel-form
        # image paths; no real services, handles or GPU access are involved.
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory); drivers=home/'drivers'; prior=home/'prior'
            drivers.mkdir(); prior.mkdir()
            names=['WinRing0x64.sys','ThrottleStop.sys']
            data=[b'fixture-read-driver',b'fixture-map-driver']
            hashes={name:hashlib.sha256(value).hexdigest() for name,value in zip(names,data)}
            for name,value in zip(names,data):
                (drivers/name).write_bytes(value); (prior/name).write_bytes(value)
            kernel=SimpleNamespace(**{name:MagicMock() for name in ('CreateFileW','CloseHandle','DeviceIoControl','CreateMutexW','WaitForSingleObject','ReleaseMutex')})
            kernel.CreateMutexW.return_value=11; kernel.WaitForSingleObject.return_value=0
            kernel.CreateFileW.side_effect=[21,22]
            images=[(chr(92)+'??'+chr(92)+str(prior/n),'REG_SZ') for n in names]
            query=subprocess.CompletedProcess([],0,'RUNNING','')
            with patch('p102.HERE',home),patch('p102.DRIVERS',hashes),patch('p102.C.WinDLL',return_value=kernel),patch('p102.Transport.sc',return_value=query) as service,patch('winreg.OpenKey'),patch('winreg.QueryValueEx',side_effect=images):
                transport=p102.Transport(True,True)
                self.assertEqual(transport.handles,[21,22])
                transport.close()
                self.assertTrue(all(call.args[0]=='query' for call in service.call_args_list))


if __name__=='__main__': unittest.main()
