     ______ _      ______ _____ 
    |  ____| |    |  ____|_   _|
    | |__  | |    | |__    | |  
    |  __| | |    |  __|   | |  
    | |    | |____| |     _| |_ 
    |_|    |______|_|    |_____| verson 0.0.1

      Find Local File Inclusion 
``` 
 - the following arguments are required: -u/--url

 - usage: flfi.py [-h] -u URL [-f SEARCH_FILE] [-d PARAM_DATA] [-c CHECK_STR] [--folder FOLDER] [-A] [-P]
               [--post-include] [-m MAX_DEPTH] [-o] [--RCE] [-i HOST_IP] [-p PORT]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Provide a target URL. If you are testing specific params please use --param or --params
  -f SEARCH_FILE, --file SEARCH_FILE
                        File to be searched for, if not specified I will attempt to search from a list of
                        common files
  -d PARAM_DATA, --param-data PARAM_DATA
                        Option if you want to define a param. THIS IS NOT NEEDED if you include ?<file>= in
                        your url.
  -c CHECK_STR, --check CHECK_STR
                        A unique string to help identify success.
  --folder FOLDER       Add a fold prefix to the traversal.
  -A                    Adds uncommon traversal strings.
  -P, --post-only       Chagne HTTP method to ONLY POST (Default is GET)
  --post-include        Chagne HTTP method to INCLUDE POST (Default is GET)
  -m MAX_DEPTH, --max MAX_DEPTH
                        Sets the max depth of traversal.(Default is 12)
  -o, --print           If files results are found print directly to terminal.
  ```

