This script was developed by capsl @ swehack IRC

ssh.py tries to detect ssh-MITM in Tor. It establish an SSH-connection through every exitnode in the Tor network and if the fingerprint is changed it classify it as a man-in-the-middle attempt. 
