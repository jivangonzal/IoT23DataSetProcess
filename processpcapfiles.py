import json
import subprocess as sp
import os


def split_pcap(capture_path: str) :
    path = './splitpcap'
    
    # Check whether the specified path exists or not
    isExist = os.path.exists(path)

    if not isExist:
  
        # Create a new directory because it does not exist 
        os.makedirs(path)
        print("The new directory was created!")

    
    cmds = ["tcpdump", "-r", capture_path, "-w", "./splitpcap/splitpcaps", "-C", "1"]
    sp.run(cmds)

    for filename in os.listdir(path):
        infilename = os.path.join(path,filename)
        if not os.path.isfile(infilename): continue
        output = os.rename(infilename, infilename + '.pcap')


def get_tshark_hexstreams(datafile: str) :
    path = './splitpcap'

    with open(datafile, "a+") as outfile:
        
        files = os.listdir(path)
        files.sort(key=lambda x: os.path.getmtime(os.path.join(path,x)))
        for filename in files :
            
            if filename.endswith(".json"):
                infilename = os.path.join(path,filename)
                if not os.path.isfile(infilename): continue
                print(infilename)
                # Opening JSON file
                with open(infilename, 'rb') as openfile:
    
                # Reading from json file
                    frames_json = json.load(openfile)
                    for frame in frames_json :
                        outfile.write(frame["_source"]["layers"]["frame"]["frame.time_epoch"][:-3] + ', ' + frame["_source"]["layers"]["frame_raw"][0] + '\n')
                        


def convert_to_json() :
    path = './splitpcap'
    
    files = os.listdir(path)
    files.sort(key=lambda x: os.path.getmtime(os.path.join(path,x)))
    for filename in files :
        
        if filename.endswith(".pcap"):
            infilename = os.path.join(path,filename)
            if not os.path.isfile(infilename): continue
            newname = infilename.replace('.pcap', '.json')

            f = open(newname, "w")
            sp.call(["tshark", "-x", "-r", infilename, "-T", "json"], stdout=f)
    




#split_pcap('2018-07-20-17-31-20-192.168.100.108.pcap')
convert_to_json()
get_tshark_hexstreams('2018-07-20-17-31-20-192.168.100.108.csv')

