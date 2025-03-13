# Packet sniffer

This project will help you to control users network traffic.

## Install requirements

$ sudo apt-get update  
$ sudo apt install libpcap-dev  
$ sudo apt install libspdlog-dev  
$ sudo apt install libfmt-dev   
$ sudo apt install libstdc++6

## Platforms

* Linux   

## Install application

Download sniffer.deb form /deb directory      

$ sudo dpkg -i sniffer.deb  

## Check application 

$ sudo service sniffer status  

## Configuration

You can change configuration file /etc/sniffer/sniffer.cfg  
Here you can add domain name like ya.ru or drom.ru.  
When you have domain name in config file    
and will try to surf this internet resources,   
this activity will write to log file as [ERROR].    
Other activity will write to log file as [INFO].    

## Log files   

$ sudo tail -n 1000 /var/log/sniffer/app_%date%.log  

* Example:  
$ sudo tail -n 500 /var/log/sniffer/app_2025-02-18.log  

* System log message:  
$ sudo tail -n 500 /var/log/sniffer/system.log  

