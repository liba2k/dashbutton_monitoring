I've started playing with Amazon Dash Buttons, while it's interesting to hack them (they have wifi, bluetooth and a mic) it's hard work, see: https://www.youtube.com/watch?v=7he02D7Wqgk

![Dash button image] (https://noveltystreet.com/wp-content/uploads/2015/08/Amazon-Dash-Button-Gatorade.jpg)

What most people do is just set the button not to buy anything and monitor arp traffic on the wifi network to detect the button's connection when it wakes up. However searching on google led me to two infrastructures. A node JS one and a python one (see: https://github.com/BraedenYoung/PracticeTracker). 


Since I don't have a PC running 24/7 to monitor the traffic, I've decided to do it from my NAS. Clearly I wasn't about to do it in python (had to get all the libpcap wrapper libraries to work on the armv7) and JS is out of the question, I've decided to take the simples libpcap example change it to monitor ARP packets and cross compile it. See attached code.
I wanted the the buttons action to still be scriptable so my code checks for a script with the MAC address and execute it. every time you wish to support another button you just need to create or copy a script to it's MAC address. The scripts need to protect themself agains multiple executions etc. 


About cross-compiling, setting up a  cross compile environment is annoying. I've found a Cross compiling toolchains in Docker images: https://github.com/dockcross/dockcross, it's really nice to use.

