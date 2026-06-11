import sys
import os
import datetime
import pyshark

OUTPUT_DIR = "/home/phdadmin/geth_project/output/captures"

def main():
    if len(sys.argv) < 4:
        print("Usage: capture.py <timeout> <iteration>")
        exit(-1)

    _timeout = int(sys.argv[1])
    _outputdir = sys.argv[2]
    _iteration = int(sys.argv[3])

    date = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    outfile = os.path.join(OUTPUT_DIR, f"capture_{_iteration}_{date}.pcap")

    print(f"Capturing traffic for {_timeout} seconds to {outfile} ...")
    capture = pyshark.LiveCapture(interface='ens224', output_file=outfile)
    capture.sniff(timeout=_timeout)
    print("Capture complete.")

if __name__ == "__main__":
    main()
