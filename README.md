This project will help you to control users network traffic.

Install instruction.
Requirement libs installation:  
sudo apt-get update  
sudo apt install libpcap-dev  
sudo apt install libspdlog-dev  

Packet Sniffer installation:  
Download sniffer.deb form /deb directory  
sudo dpkg -i sniffer.deb  

Check that system working.  
sudo service sniffer status  

You can check results of work   
sudo tail -n 1000 /var/log/sniffer/app_%date%.log
Example:
sudo tail -n 500 /var/log/sniffer/app_2025-02-18.log

