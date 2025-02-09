This project will help you to control users network traffic.

Install instruction.
Requirement libs installation:
sudo apt-get update
sudo apt install libpcap-dev

Packet Sniffer installation:
mkdir sniffer
Copy deb packet to sniffer directory.
cd sniffer
sudo dpkg -i packet_sniffer.deb


Check that system working.
sudo service packetsniffer status

You can check results of work 
sudo cat /var/log/sniffer_result.log
