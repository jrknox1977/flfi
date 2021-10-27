     ______ _      ______ _____ 
    |  ____| |    |  ____|_   _|
    | |__  | |    | |__    | |  
    |  __| | |    |  __|   | |  
    | |    | |____| |     _| |_ 
    |_|    |______|_|    |_____| verson 0.0.1

      Find Local File Inclusion 
``` 
 - the following arguments are required: -u/--url

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Provide a target URL. If you are testing specific params please use --param or --params
  -f SEARCH_FILE, --file SEARCH_FILE
                        File to be searched for, if not specified I will attempt to search from a list of common files
  -d PARAM_DATA, --param-data PARAM_DATA
                        Option if you want to define a param. THIS IS NOT NEEDED if you include ?<file>= in your url.
  -c CHECK_STR, --check CHECK_STR
                        A unique string to help identify success.
  -C, --cookie-only     USE ONLY COOKIE METHOD to attempt to use directory traversal, must supply the target cookie with -d or --params-data.
  --cookie-include      INCLUDE COOKIE METHOD to attempt to use directory traversal, must supply the target cookie with -d or --params-data.
  --folder FOLDER       Add a fold prefix to the traversal.
  -A                    Adds uncommon traversal strings and all methods.
  -P, --post-only       Chagne HTTP method to ONLY POST (Default is GET)
  --post-include        Chagne HTTP method to INCLUDE POST (Default is GET)
  -m MAX_DEPTH, --max MAX_DEPTH
                        Sets the max depth of traversal.(Default is 12)
  -o, --print           If files results are found print directly to terminal.
  --RCE                 Will attempt RCE on target. Default is command is echo Hello FLFI!
  --RCE-basic-shell     Execute basic reverse shell, MAKE SURE to start a listener on the same port you specified in --lport
  --lhost LHOST         Set the local host for RCE
  --lport LPORT         Port for reverse shell
  --rport RPORT         Port Target will use to connect to the local listener for shell.
  ```

