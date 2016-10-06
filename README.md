### ARP Cache poisoner


### Basic usage

with ARP replies
```bash
sudo ./acp 192.168.0.1 192.168.0.15
```

or with ARP request
```bash
sudo ./acp -q 192.168.0.1 192.168.0.15
```
### Dependencies
- `gcc`
- `autoconf`
- `automake`
- `libtool`
- `m4`
- `libpcap` 

You can usually install these through you distributions package manager.

##### Debian and friends
```
sudo apt-get install gcc autoconf automake libtool m4 libpcap-dev
```
##### Arch Linux

```
sudo pacman -S gcc autoconf automake libtool m4 libpcap
```

### Build and Installation

To build the project run the following commands in the project root:
```
./autogen.sh
```
then
```
./configure
```
After the makefiles have been generated, build the project by running:
```bash
make
```
At this point you can run `acp` directly from the `src` directory, but if you wish to install it so that you can run it from anywhere run:
```bash
sudo make install
```

The install can be undone by running:
```bash
sudo make uninstall
```

