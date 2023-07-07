def clear(_):
    if _: input()
    system('cls')

def info():
    print(
        colored(' [*] Your PC/exec. Informations:', 'dark_grey'),

f'''
    Platform:\t\t {platform.system()} - {platform.architecture()[0]}
    Py. Version:\t Python {platform.python_version()[0]}
    
    --termcolor = \"{version('termcolor')}\"
    --psutil = \"{version('psutil')}\"
    --scapy = \"{version('scapy')
}\"\n''')

def getSize(bytes):
    for unit in ['', 'K', 'M', 'G', 'T', 'P']:
        if bytes < 1024:
            return f'{bytes:.2f}{unit}B'
        bytes /= 1024

def processPacket(packet):
    global PID2traffic

    try: packet_connection = (packet.sport, packet.dport)

    except (AttributeError, IndexError): pass
    else:
        packetPID = connection2PID.get(packet_connection)

        if packetPID:
            if packet.src in allMACs:
                PID2traffic[packetPID][0] += len(packet)

            else: PID2traffic[packetPID][1] += len(packet)

def getConn(self):
    global connection2PID

    while self.running:
        for c in psutil.net_connections():
            if c.laddr and c.raddr and c.pid:
                connection2PID[(c.laddr.port, c.raddr.port)] = c.pid
                connection2PID[(c.raddr.port, c.laddr.port)] = c.pid

        time.sleep(1)

def printPID2traffic():
    global globalDF

    processes = []
    for PID, traffic in PID2traffic.items():
        try: p = psutil.Process(PID)

        except psutil.NoSuchProcess: continue

        name = p.name()
        try: create_time = datetime.fromtimestamp(p.create_time())

        except OSError: create_time = datetime.fromtimestamp(psutil.boot_time())

        process = {
            'PID': PID, 'Name': name, 'Create time': create_time,
            'Upload': traffic[0], 'Download': traffic[1],
        }

        try:
            process['Upload Speed'] = traffic[0] - globalDF.at[PID, 'Upload']
            process['Download Speed'] = traffic[1] - globalDF.at[PID, 'Download']

        except (KeyError, AttributeError):
            process['Upload Speed'] = traffic[0]
            process['Download Speed'] = traffic[1]

        processes.append(process)

    df = pd.DataFrame(processes, index = [f' {i+1}' for i in range(len(processes))])
    try: df.sort_values('Download', inplace = True, ascending = False)

    except KeyError: pass

    printingDF = df.copy()

    clear(''); help(obj.main)

    try:
        printingDF['Download'] = printingDF['Download'].apply(getSize)
        printingDF['Upload'] = printingDF['Upload'].apply(getSize)
        printingDF['Download Speed'] = printingDF['Download Speed'].apply(getSize).apply(lambda s: f'{s}/s')
        printingDF['Upload Speed'] = printingDF['Upload Speed'].apply(getSize).apply(lambda s: f'{s}/s')

        info(); print(
            colored(''' [*] Sniffing NET Usage:
\n''', 'green'), printingDF.to_string()
        )

    except KeyError: pass
    globalDF = df

def printStats(self):
    while self.running:
        time.sleep(1); printPID2traffic()

def main(self):
    '''
    ** MADE WITH/FOR:
        Platform:\t Windows
        Py. Version:\t Python 3

        --termcolor = "2.2.0"
        --psutil = "5.9.4"
        --scapy = "2.5.0"

    ** FORMATS:
        PID; Name; Create time; Upload; Download; Upload Speed; Download Speed

    FUNCTION: Sniff Your Network Usage per Process.
    
    ** GET A TIME TO THE PROGRAM AFTER "CTRL+C".
    '''
    
    self.running = True

    self.printingThread = Thread(target = self.printStats)
    self.printingThread.start()

    connectionsThread = Thread(target = self.getConn)
    connectionsThread.start()

    sniff(prn = processPacket, store = False)
    self.running = False

from importlib.metadata import version
from collections import defaultdict
from termcolor import colored
from threading import Thread
from scapy.all import *
from os import system

import platform, psutil, pandas as pd

obj = type('Obj', (object, ), {'main': main, 'getConn': getConn, 'printStats': printStats})
start = obj()

allMACs, globalDF = {iface.mac for iface in ifaces.values()}, None
connection2PID, PID2traffic = {}, defaultdict(lambda: [0, 0])

try:
    clear(''); start.main()
except KeyboardInterrupt: exit(0)
except Exception as err: input(colored(f'\n {type(err).__name__}: {err}.', 'red'))