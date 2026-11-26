# 🤖 Gemini PC Workspace (Custom MCP Server)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP Protocol](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-green.svg)](https://modelcontextprotocol.io/)

เชื่อมต่อ **Google Gemini** บนเว็บเข้ากับคอมพิวเตอร์ของคุณโดยตรงผ่าน **Model Context Protocol (MCP)** สั่งให้ AI อ่านไฟล์, สร้างไฟล์, แก้ไขโค้ด และสั่งรันคำสั่งบนเครื่องได้เหมือนมี **JARVIS ประจำตัว!**

---

## ✨ จุดเด่น (Features)

- 📂 **จัดการไฟล์ในเครื่อง:** สั่งให้ Gemini ดูรายชื่อไฟล์, อ่านเนื้อหา, หรือสร้างไฟล์ใหม่ลงในโฟลเดอร์ทำงานบน PC
- ⚡ **One-Click Start:** มีไฟล์ `start.bat` ให้ดับเบิ้ลคลิกเดียว รันทั้งเซิร์ฟเวอร์และเปิด Cloudflare Tunnel อัตโนมัติ
- 🛡️ **ปลอดภัยด้วยระบบ Sandbox:** จำกัดสิทธิ์การเข้าถึงไฟล์เฉพาะในโฟลเดอร์ที่กำหนด ป้องกัน Path Traversal
- 🔒 **Command Whitelist:** ป้องกันการสั่งคำสั่งอันตราย รันได้เฉพาะคำสั่งปลอดภัยที่อนุญาตเท่านั้น
- 🌐 **ไม่ต้องเปิดพอร์ตเราเตอร์:** ใช้งานผ่าน Cloudflare Tunnel (ฟรี 100% ไม่ต้องสมัครสมาชิก ไม่ต้องใช้ IP จริง)
- 🔄 **รองรับ MCP ทุกเวอร์ชัน:** มี Compatibility Layer ในตัว แก้ปัญหา `ModuleNotFoundError` และ DNS Rebinding อัตโนมัติ

---

## 🛠️ เครื่องมือที่ Gemini สั่งงานได้ (Available Tools)

| Tool Name | คำอธิบาย | ตัวอย่างการสั่งในแชท |
| :--- | :--- | :--- |
| `list_files` | แสดงรายชื่อไฟล์ทั้งหมดในโฟลเดอร์ทำงาน | *"ดูรายชื่อไฟล์ทั้งหมดในโฟลเดอร์ทำงานหน่อย"* |
| `read_file` | อ่านเนื้อหาไฟล์ข้อความ | *"อ่านเนื้อหาในไฟล์ notes.txt ให้ฟังหน่อย"* |
| `write_file` | สร้างหรือบันทึกไฟล์ใหม่ลงในเครื่อง | *"ช่วยเขียนสรุปแผนงานลงไฟล์ plan.md"* |
| `run_allowed_command` | รันคำสั่งปลอดภัย (`git_status`, `python_version`, `list_dir`) | *"เช็คสถานะ git status ในเครื่องให้ที"* |

---

## 🚀 เริ่มต้นใช้งานใน 3 ขั้นตอน (Quick Start)

### ขั้นตอนที่ 1: ดาวน์โหลดโปรเจกต์
```bash
git clone https://github.com/108ido/gemini-pc-mcp.git
cd gemini-pc-mcp
```

### ขั้นตอนที่ 2: ดับเบิลคลิก `start.bat`

ต้องมี **Python 3.10+** และ **cloudflared** ในเครื่องก่อน ถ้ายังไม่มี cloudflared ให้ติดตั้งด้วยคำสั่งนี้:
```bash
winget install --id Cloudflare.cloudflared
```

ตอนรัน `start.bat` จะทำให้อัตโนมัติทั้งหมด:
1. ติดตั้งไลบรารีที่ต้องใช้ (เฉพาะครั้งแรก)
2. สร้างรหัสลับเก็บในไฟล์ `.mcp_secret` (เฉพาะครั้งแรก ไฟล์นี้ไม่ขึ้น git)
3. เปิด MCP server ที่พอร์ต 8000
4. เปิด Cloudflare Tunnel แล้วแสดงลิงก์สำหรับเอาไปใส่ใน Gemini บนจอ

| โหมด | ใช้เมื่อ | ลิงก์ |
|---|---|---|
| **Quick Tunnel** (ค่าเริ่มต้น) | ไม่ต้องสมัครอะไร ฟรี | `https://xxxx.trycloudflare.com/<secret>/mcp` (เปลี่ยนทุกครั้งที่เปิดใหม่) |
| **Named Tunnel** | มีโดเมนใน Cloudflare อยู่แล้ว อยากได้ลิงก์ถาวร | วาง token ไว้ในไฟล์ `.tunnel_token` → `https://<โดเมนของคุณ>/<secret>/mcp` |

`<secret>` = ข้อความในไฟล์ `.mcp_secret` ซึ่ง `start.bat` จะแสดงลิงก์เต็มพร้อมรหัสให้บนจออยู่แล้ว

> ⚠️ **Host Allowlist (ป้องกัน DNS rebinding):** server ตรวจ `Host` header ของทุกคำขอ ค่าเริ่มต้นอนุญาตเฉพาะ `127.0.0.1:8000` และ `localhost:8000` คำขอที่มาผ่าน Tunnel จะได้รหัส `421` จนกว่าจะเพิ่ม hostname ของ tunnel ลงใน `MCP_ALLOWED_HOSTS` สำหรับ Quick Tunnel ให้รอให้ cloudflared แสดง hostname แล้วปิดหน้าต่าง server เดิม ตั้งค่าแล้วรันใหม่ (tunnel เดิมยังเปิดอยู่):
> ```bat
set MCP_ALLOWED_HOSTS=127.0.0.1:8000,localhost:8000,xxxx.trycloudflare.com
python server.py
```

#### 👉 รันเองผ่าน Terminal
```bash
pip install -r requirements.txt
set MCP_ALLOWED_HOSTS=127.0.0.1:8000,localhost:8000,your-tunnel-host.example
python server.py
cloudflared tunnel --url http://127.0.0.1:8000
```

---

### ขั้นตอนที่ 3: วางลิงก์ใน Google Gemini

1. เปิด **Google Gemini** ([gemini.google.com](https://gemini.google.com)) แล้วไปที่ **แสดงเพิ่ม › ปรับแต่ง › เครื่องมือเชื่อมต่อ › + กำหนดเอง**
2. วางลิงก์ `https://.../<secret>/mcp` ลงในช่อง **URL ของเซิร์ฟเวอร์ MCP** → กด **ถัดไป** → ติ๊กยอมรับ → กด **เชื่อมต่อ**
3. ถ้าเชื่อมต่อสำเร็จ จะเห็น **PC Workspace** พร้อมเครื่องมือ 6 ตัว จากนั้นลองพิมพ์สั่งใน Gemini ได้เลย เช่น *"ใช้ PC Workspace สร้างไฟล์ hello.html …"*

> ถ้าใช้ Quick Tunnel ลิงก์จะเปลี่ยนทุกครั้งที่เปิด `start.bat` ใหม่ ต้องลบ connector ตัวเก่าใน Gemini แล้วเพิ่มตัวใหม่ด้วยลิงก์ใหม่ทุกครั้ง

---

## 📂 โฟลเดอร์ทำงาน (Workspace)

ค่าเริ่มต้นคือโฟลเดอร์ของโปรเจกต์นี้ ถ้าต้องการเปลี่ยน ให้กำหนดผ่าน Environment Variable `MCP_WORKSPACE`:

```powershell
$env:MCP_WORKSPACE = "C:\Your\Custom\Path"
python server.py
```

---

## ⚠️ ความปลอดภัย

- ถ้าไม่มีรหัสลับ server จะตอบ 404 ทุก request ถ้ารหัสหลุดเมื่อไหร่ ให้สร้าง `.mcp_secret` ใหม่แล้วรีสตาร์ท server
- MCP **อ่านหรือแสดงไม่ได้**: `.mcp_secret`, `.tunnel_token`, `.git`, `.env` และทุกอย่างที่อยู่นอกโฟลเดอร์ทำงาน
- MCP **เขียนไม่ได้** ไฟล์ที่ Python/Windows โหลดหรือรันได้ทั้งชุด (`.py .pyw .pyc .pyo .pyd .pyz .pth .so .bat .cmd .com .exe .dll .scr .ps1 .vbs .js .wsf .hta .lnk .url .reg .msi` และอื่นๆ) กันเขียนทับ `server.py`/`start.bat` และกัน shadow โมดูล Python ในโฟลเดอร์แอป
- ชื่อไฟล์ลับเทียบแบบไม่สนตัวพิมพ์ (`.GIT` ถือเป็น `.git`) และตรวจพาธที่ resolve แล้วอีกรอบ กัน alias ชื่อสั้น 8.3 บน Windows
- ขีดจำกัดทั้งหมดตั้งผ่านตัวแปร: `MCP_MAX_FILE_BYTES` (25 MiB) สำหรับอ่าน/เขียน/Base64/ดาวน์โหลด, `MCP_MAX_LIST_ENTRIES` (5000) และ `MCP_MAX_LIST_DEPTH` (32) สำหรับ `list_files`, `MCP_COMMAND_TIMEOUT` (15 วินาที) และ output สูงสุด 256 KiB สำหรับ `run_allowed_command`
- `git_status` ปิด fsmonitor hook ของ repo และ access log ของ uvicorn ปิดบังรหัสลับใน URL
- ถ้า token ของ tunnel หลุด ให้ไปกด Refresh token ใน Cloudflare Zero Trust แล้วอัปเดตไฟล์ `.tunnel_token`

---

## 📄 License

โปรเจกต์นี้เผยแพร่ภายใต้สัญญาอนุญาต [MIT License](LICENSE) สามารถนำไปต่อยอด ดัดแปลง และใช้งานได้ฟรี!
