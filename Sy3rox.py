import os
import random
import shutil
import winreg
import string
import glob
import win32com.client
import threading
import requests
import re
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog
import subprocess
import platform
import random
import socket
import ctypes  # Windows özel kütüphane
from ctypes import windll, byref, wintypes
import winsound
import pyautogui
from transformers import pipeline


class VirusScanner(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.sqlerrlist = []
        self.progressbar = ttk.Progressbar(self)
        self.statusbar = tk.Label(self, text="Status: Evil Mode")
        self.proxy_list = []
        self.initialize()

    def initialize(self):
        self.title("Scanner")
        self.geometry("800x600")

        self.progressbar.pack(fill=tk.X, padx=10, pady=10)
        self.statusbar.pack(side=tk.BOTTOM, pady=5)

        start_button = tk.Button(self, text="Start", command=self.start_scan)
        start_button.pack()

        self.load_proxy_list()  # Proxy listesini yükle
        self.add_ip_access()
        self.add_port_access()
        self.add_region_access()
        self.add_ip_buttons()
        self.add_emergency_button()  # Acil Durum Butonunu ekle
        self.add_custom_button()  # Özel Butonu ekle
        self.add_battery_access()  # Batarya Durumu Butonunu ekle
        self.add_file_button()  # Dosya Gönder Butonunu ekle

        # Transformer modelini yükle
        self.classifier = pipeline("text-classification", model="bert-base-uncased")

    def start_scan(self):
        # Başlat düğmesine tıklandığında yapılacak işlemler
        threading.Thread(target=self.scan_process).start()

    def scan_process(self):
        self.show_notification("Scan Started")

        ip = self.ip_entry.get()
        url = f"http://{ip}"

        port = self.port_entry.get()
        port = int(port) if port.isdigit() else None

        region_code = self.region_entry.get()
        block_url = f"http://ip-api.com/json/{region_code}"

        try:
            block_response = requests.get(block_url)
            block_data = block_response.json()
            if block_data["status"] == "fail":
                self.show_notification("Region Blocked\nInvalid region code or region not found!")
                return

            restricted_ips = block_data["query"]
            region = block_data["region"]

            if ip in restricted_ips:
                self.show_notification("Access Denied\nAccess to this IP address is blocked.")
                return

            ping_result = subprocess.run(["ping", "-n", "4", ip], capture_output=True, text=True)
            if ping_result.returncode == 0:
                self.show_notification("Ping Status\nPing to IP successful!")
                winsound.Beep(1000, 500)  # Play a beep sound at 1000 Hz frequency for 500 milliseconds
            else:
                self.show_notification("Ping Status\nPing to IP failed!")

            self.show_notification(f"IP Address\nEntered IP Address: {ip}")

            screenshot = pyautogui.screenshot()
            screenshot.save("screenshot.png")

            if self.check_ip_connectivity_with_timeout(ip):
                self.show_notification(f"Connection Status\nConnection to {ip} successful!")
            else:
                self.show_notification(f"Connection Status\nConnection to {ip} failed!")

            response = requests.get(url, proxies={"http": self.get_random_proxy(), "https": self.get_random_proxy()})
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', response.text)
            if emails:
                email_list = "\n".join(emails)
                self.show_notification(f"Email Addresses\nFound Email Addresses:\n{email_list}")
            else:
                self.show_notification("Email Addresses\nNo email addresses found.")

            device_info = self.get_device_info()
            self.show_notification(f"Device Information\n{device_info}")

            self.get_battery_status_process()  # Batarya durumu işlemini başlat

        except requests.RequestException:
            self.show_notification("Error\nAn error occurred while sending the request.")

    def add_emergency_button(self):
        self.emergency_button = tk.Button(self, text="Emergency", command=self.trigger_emergency)
        self.emergency_button.pack(pady=20)

    def trigger_emergency(self):
        response = messagebox.askyesno("Warning", "Do you want to trigger the emergency button?")
        if response:
            # Burada acil durum senaryosuna ilişkin işlemleri gerçekleştirebilirsiniz.
            # Örneğin, gerekli kişilere bildirim gönderme, acil durum planını uygulama, vb.
            messagebox.showinfo("Notification", "Emergency triggered!")

    def add_ip_access(self):
        self.ip_label = tk.Label(self, text="IP Address:")
        self.ip_entry = tk.Entry(self)
        self.ip_label.pack()
        self.ip_entry.pack()

    def add_port_access(self):
        self.port_label = tk.Label(self, text="Port:")
        self.port_entry = tk.Entry(self)
        self.port_label.pack()
        self.port_entry.pack()

    def add_region_access(self):
        self.region_label = tk.Label(self, text="Region Code:")
        self.region_entry = tk.Entry(self)
        self.region_label.pack()
        self.region_entry.pack()

    def add_ip_buttons(self):
        self.get_ip_button = tk.Button(
            self, text="Find Emails, Ping and Scan", command=self.find_emails_ping_and_scan
        )
        self.get_ip_button.pack()

        self.scan_button = tk.Button(
            self, text="Scan", command=self.scan_port
        )
        self.scan_button.pack()

        self.speedup_button = tk.Button(
            self, text="Speed Up TCP/IP", command=self.speedup_ip
        )
        self.speedup_button.pack()

        self.protect_button = tk.Button(
            self, text="IP Protection", command=self.protect_ip
        )
        self.protect_button.pack()

    def show_notification(self, message):
        messagebox.showinfo("Notification", message)

    def load_proxy_list(self):
        with open("proxy.txt", "r") as file:
            self.proxy_list = [line.strip() for line in file.readlines()]

    def find_emails_ping_and_scan(self):
        threading.Thread(target=self.find_emails_ping_and_scan_process).start()

    def find_emails_ping_and_scan_process(self):
        ip = self.ip_entry.get()
        url = f"http://{ip}"

        port = self.port_entry.get()
        port = int(port) if port.isdigit() else None

        region_code = self.region_entry.get()
        block_url = f"http://ip-api.com/json/{region_code}"

        try:
            block_response = requests.get(block_url)
            block_data = block_response.json()
            if block_data["status"] == "fail":
                self.show_notification("Region Blocked\nInvalid region code or region not found!")
                return

            restricted_ips = block_data["query"]
            region = block_data["region"]

            if ip in restricted_ips:
                self.show_notification("Access Denied\nAccess to this IP address is blocked.")
                return

            threading.Thread(target=self.ping_ip, args=(ip,)).start()

            self.show_notification(f"IP Address\nEntered IP Address: {ip}")

            screenshot = pyautogui.screenshot()
            screenshot.save("screenshot.png")

            threading.Thread(target=self.check_ip_connectivity_with_timeout, args=(ip,)).start()

            response = requests.get(url, proxies={"http": self.get_random_proxy(), "https": self.get_random_proxy()})
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', response.text)
            if emails:
                email_list = "\n".join(emails)
                self.show_notification(f"Email Addresses\nFound Email Addresses:\n{email_list}")
            else:
                self.show_notification("Email Addresses\nNo email addresses found.")

            threading.Thread(target=self.get_device_info_process).start()

            self.get_battery_status_process()  # Batarya durumu işlemini başlat

        except requests.RequestException:
            self.show_notification("Error\nAn error occurred while sending the request.")

    def ping_ip(self, ip):
        ping_result = subprocess.run(["ping", "-n", "4", ip], capture_output=True, text=True)
        if ping_result.returncode == 0:
            self.show_notification("Ping Status\nPing to IP successful!")
            winsound.Beep(1000, 500)  # Play a beep sound at 1000 Hz frequency for 500 milliseconds
        else:
            self.show_notification("Ping Status\nPing to IP failed!")

    def check_ip_connectivity_with_timeout(self, ip, timeout=1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            result = sock.connect_ex((ip, 80))
            if result == 0:
                self.show_notification(f"Connection Status\nConnection to {ip} successful!")
            else:
                self.show_notification(f"Connection Status\nConnection to {ip} failed!")
        except socket.error:
            self.show_notification("Error\nAn error occurred during connection check.")
        finally:
            sock.close()

    def get_random_proxy(self):
        return random.choice(self.proxy_list)

    def get_device_info_process(self):
        threading.Thread(target=self.get_device_info).start()

    def get_device_info(self):
        device_info = "Devices:\n"
        if platform.system() == "Windows":
            device_info += self.get_windows_devices()
        elif platform.system() == "Linux":
            device_info += self.get_linux_devices()
        else:
            device_info += "Device information not available."
        return device_info

    def get_windows_devices(self):
        devices = ""
        try:
            wmi = win32com.client.GetObject("winmgmts:")
            for disk_drive in wmi.InstancesOf("Win32_DiskDrive"):
                devices += f"{disk_drive.Caption} - Version: {disk_drive.FirmwareRevision}\n"
            for network_adapter in wmi.InstancesOf("Win32_NetworkAdapter"):
                devices += f"{network_adapter.Description} - Version: {network_adapter.DriverVersion}\n"
        except Exception:
            devices = "Device information not available."
        return devices

    def get_linux_devices(self):
        devices = ""
        try:
            devices += subprocess.run(["lshw", "-short"], capture_output=True, text=True).stdout
        except subprocess.CalledProcessError:
            devices = "Device information not available."
        return devices

    def scan_port(self):
        threading.Thread(target=self.scan_port_process).start()

    def scan_port_process(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        port = int(port) if port.isdigit() else None

        if port is not None:
            self.show_notification(f"Port Scan\nScanning...")

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)

                result = sock.connect_ex((ip, port))
                if result == 0:
                    self.show_notification(f"Port Scan\n{ip}:{port} is open!")
                else:
                    self.show_notification(f"Port Scan\n{ip}:{port} is closed!")
            except socket.error:
                self.show_notification("Error\nAn error occurred during port scanning.")
            finally:
                sock.close()
        else:
            self.show_notification("Error\nPlease enter a valid port number.")

    def speedup_ip(self):
        threading.Thread(target=self.speedup_ip_process).start()

    def speedup_ip_process(self):
        ip = self.ip_entry.get()

        try:
            # Reset IP and DNS settings
            reset_network_settings()

            self.show_notification("IP Speedup\nIP and DNS settings reset.")
        except Exception as e:
            self.show_notification(str(e))

    def protect_ip(self):
        threading.Thread(target=self.protect_ip_process).start()

    def protect_ip_process(self):
        ip = self.ip_entry.get()
        url = f"http://ip-api.com/json/{ip}"

        try:
            response = requests.get(url)
            ip_data = response.json()

            if ip_data["status"] == "fail":
                self.show_notification("IP Protection\nFailed to retrieve IP information.")
                return

            if "proxy" in ip_data and ip_data["proxy"]:
                self.show_notification("IP Protection\nThis IP belongs to a proxy server.")
            elif "vpn" in ip_data and ip_data["vpn"]:
                self.show_notification("IP Protection\nThis IP belongs to a VPN server.")
            elif "mobile" in ip_data and ip_data["mobile"]:
                self.show_notification("IP Protection\nThis IP belongs to a mobile network.")
            else:
                self.show_notification("IP Protection\nThis IP is detected as safe.")
        except requests.RequestException:
            self.show_notification("Error\nAn error occurred while sending the request.")

    def add_custom_button(self):
        custom_button_text = "Custom Button"
        custom_button_command = self.custom_button_action

        self.custom_button = tk.Button(
            self, text=custom_button_text, command=custom_button_command
        )
        self.custom_button.pack()

    def custom_button_action(self):
        threading.Thread(target=self.custom_button_action_process).start()

    def custom_button_action_process(self):
        ip = self.ip_entry.get()
        threading.Thread(target=self.get_device_info_process).start()
        self.show_notification(f"Device Information\nIP: {ip}")

    def add_battery_access(self):
        self.battery_button = tk.Button(
            self, text="Battery Status", command=self.get_battery_status
        )
        self.battery_button.pack()

    def get_battery_status(self):
        threading.Thread(target=self.get_battery_status_process).start()

    def get_battery_status_process(self):
        if platform.system() == "Windows":
            ac_line_status, battery_flag, battery_percent, battery_life_time, battery_full_life_time = self.retrieve_battery_status()

            if ac_line_status == 1:
                ac_line_status_str = "Plugged in."
            else:
                ac_line_status_str = "Not plugged in."

            if battery_flag == 128:
                battery_flag_str = "Battery full."
            elif battery_flag == 255:
                battery_flag_str = "Battery cannot be charged."
            elif battery_flag == 0:
                battery_flag_str = "Battery is in a chargeable state."
            else:
                battery_flag_str = "Unknown battery status."

            battery_info = f"Battery Percentage: {battery_percent}\nBattery Life Time (seconds): {battery_life_time}\nBattery Full Life Time (seconds): {battery_full_life_time}"

            self.show_notification(f"Battery Status\n{ac_line_status_str}\n{battery_flag_str}\n{battery_info}")
        else:
            self.show_notification("Error\nBattery status can only be accessed on Windows.")

    def retrieve_battery_status(self):
        class SYSTEM_POWER_STATUS(ctypes.Structure):
            _fields_ = [
                ("ACLineStatus", wintypes.BYTE),
                ("BatteryFlag", wintypes.BYTE),
                ("BatteryLifePercent", wintypes.BYTE),
                ("Reserved1", wintypes.BYTE),
                ("BatteryLifeTime", wintypes.DWORD),
                ("BatteryFullLifeTime", wintypes.DWORD),
            ]

        SYSTEM_POWER_STATUS_P = ctypes.POINTER(SYSTEM_POWER_STATUS)
        GetSystemPowerStatus = windll.kernel32.GetSystemPowerStatus
        GetSystemPowerStatus.argtypes = [SYSTEM_POWER_STATUS_P]
        GetSystemPowerStatus.restype = wintypes.BOOL

        status = SYSTEM_POWER_STATUS()
        if not GetSystemPowerStatus(ctypes.pointer(status)):
            raise ctypes.WinError()

        ac_line_status = status.ACLineStatus
        battery_flag = status.BatteryFlag
        battery_percent = status.BatteryLifePercent
        battery_life_time = status.BatteryLifeTime
        battery_full_life_time = status.BatteryFullLifeTime

        return (
            ac_line_status,
            battery_flag,
            battery_percent,
            battery_life_time,
            battery_full_life_time,
        )

    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.show_notification(f"Selected File: {file_path}")
            # Perform file sending operation here
        else:
            self.show_notification("Error\nNo file selected.")

    def add_file_button(self):
        self.file_button = tk.Button(self, text="Send File", command=self.send_file)
        self.file_button.pack()
        

if __name__ == "__main__":
    scanner = VirusScanner()
    scanner.mainloop()
