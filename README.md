# STUN Client
Translates NAT and punches through a UDP port.
## Example usage
```bash
./stun stun.l.google.com 19302 2000
```
Where 19302 is the stun server port, and 2000 is the desired port you want to obtain a translation of. 
Example output:
```bash
195.159.235.214:62416
```
Which is your public IP, and the translated and open version of UDP port 2000.
## Building
```bash
mkdir build
cd build
cmake ..
make
```
### Optional installation
```bash
make install
```