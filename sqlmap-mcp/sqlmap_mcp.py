import sys
from typing import List
import subprocess
from fastmcp import FastMCP
import re

mcp = FastMCP("sqlmap_mcp",debug=True,log_level="DEBUG")
SQLMAP_PATH = ""

@mcp.tool()
def do_sqlmap(url: str,sqlmap_args: List[str] = []) -> str:
    '''
    Call sqlmap for scanning
    url: The url address to be scanned
    sqlmap_args:
    Additional SQLmap arguments
   -g GOOGLEDORK       Process Google dork results as target URLs

  Request:
    These options can be used to specify how to connect to the target URL

    --data=DATA         Data string to be sent through POST (e.g. "id=1")
    --cookie=COOKIE     HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
    --random-agent      Use randomly selected HTTP User-Agent header value
    --proxy=PROXY       Use a proxy to connect to the target URL
    --tor               Use Tor anonymity network
    --check-tor         Check to see if Tor is used properly

  Injection:
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --dbms=DBMS         Force back-end DBMS to provided value

  Detection:
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)

  Techniques:
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")

  Enumeration:
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --passwords         Enumerate DBMS users password hashes
    --dbs               Enumerate DBMS databases
    --tables            Enumerate DBMS database tables
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table(s) to enumerate
    -C COL              DBMS database table column(s) to enumerate

  Operating system access:
    These options can be used to access the back-end database management
    system underlying operating system

    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC

  General:
    These options can be used to set some general working parameters

    --batch             Never ask for user input, use the default behavior
    --flush-session     Flush session files for current target

  Miscellaneous:
    These options do not fit into any other category

    --wizard            Simple wizard interface for beginner users>
    '''
    command_list = ['python3', SQLMAP_PATH, url] + sqlmap_args + ["--batch"]
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, check=True)
        if "do you want to use common password suffixes? (slow!) [y/N]" in result.stdout:
            p = re.compile(r"do you want to use common password suffixes\? \(slow!\) \[y/N\](.*?)(?:Database:)",re.DOTALL)
            match = p.search(result.stdout)
            if match:
                result_text = result.stdout.replace(match.group(1),"")
            else:
                result_text = result.stdout
            return result_text
        else:
            return result.stdout
    except Exception as e:
        return str(e)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        pass
    else:
        print("没有提供sqlmap路径，例如：python3 sqlmap_mcp.py /you/sqlmap/path/sqlmap.py")
        sys.exit(0)
    SQLMAP_PATH = sys.argv[1]
    mcp.run(transport="sse",port=8009)
