# STUN Client
Translates NAT and punches through a UDP port. Also determines NAT type.
## Example usage
```bash
./stun-client 2020
```
Where 2000 is the desired port you want to obtain a translation of. 
Example output:
```json
{
        "ext_ip" : "84.210.144.140",
        "ext_port" : "2020",
        "nat_type" : "symmetric"
}
```
Which is your external IP and port.
## Building
First clone, remember submodules:
```bash
git clone --recurse-submodules git@github.com:domoslabs/stun-client.git
```
Then build as usual:
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