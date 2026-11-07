# P102 PCIe Gen2

Windows 10/11 x64 的 NVIDIA P102-100 PCIe 2.0 修改与后台保持工具。

## 使用

运行单文件 `P102Gen2.exe`，点击“启动”并完成管理员授权。成功后窗口自动最小化；“停止”退出保持，关闭窗口不会停止后台。“开机自启”默认关闭，启用后由 SYSTEM 在开机延迟 30 秒运行，无需登录。

自动识别 P102，首次安装绑定完整设备实例；多张未绑定的 P102 会拒绝自动选卡。每次操作重新核验设备身份及独占上游桥。没有日志模块、日志按钮或持续写盘，运行状态使用共享内存。安装配置、开机设置和原始驱动策略备份保存在 ProgramData\P102Gen2，启动副本保存在 Program Files\P102Gen2。

需要已安装可用的 NVIDIA 驱动，且系统允许加载所需硬件访问驱动。如果驱动被阻止，程序应报告失败；本项目不自动更改系统安全设置。

## 从源码构建

安装 Windows x64 Python 3.13（包含 Tcl/Tk），在仓库目录运行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

脚本从固定上游提交下载两个驱动，并验证 SHA256，然后运行测试并生成 `dist/P102Gen2.exe`。发布时请同时提供 THIRD-PARTY.txt 和相应第三方许可文本。驱动二进制不包含在源码提交中。

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s src -p test_minimal.py
.\dist\P102Gen2.exe --self-test .\self-test.json
```

自检只检查封装及运行环境，不执行硬件修改。源码 GUI 的安装流程面向冻结后的 EXE，请使用构建产物运行。

## 实现与验证范围

详见 [RESEARCH.md](RESEARCH.md)。通过 MMIO 掩码修改 Pascal 链路相关寄存器，重新识别 PCIe capability，设置端点和独占上游桥的目标速率并重新训练链路；后台轮询保持状态。只在 capability v2 时访问 Link Control 2。没有刷写 VBIOS、熔丝或修改 PCI ID，也不承诺 Gen3 或增加物理通道数。

本机硬件核心已完成三轮启动、带宽验证与停止：实测 Gen2 x4，数据校验通过，单向约 1.46–1.68 GB/s。12 项单元测试通过。0.4.3 修复了普通用户界面读取 SYSTEM 保持进程状态时的权限误判，并通过冻结程序自检；尚未完成该版本完整硬件端到端复测、整机冷启动或其他电脑/Windows 11 的实测。停止时尝试恢复内存中的原始寄存器字段；后台异常退出时不能保证恢复。

仓库根目录原有 EXE 是历史上传文件；源码版本以 `src/app.py` 中 VERSION 为准，建议自行构建当前版本。

## 许可与来源

保留仓库原有 GPL-3.0 LICENSE。第三方来源与固定驱动校验值见 [THIRD-PARTY.txt](THIRD-PARTY.txt)，各第三方组件适用其自身许可。
