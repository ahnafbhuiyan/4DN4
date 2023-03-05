#!/usr/bin/python3

######################################################
# The ipaddress module can be used to manipulate IPv4 and IPv6
# addresses, networks and interfaces.

# See https://docs.python.org/3/library/ipaddress.html for a full
# description.

import ipaddress

######################################################
# IP address objects.
######################################################

######################################################

def output_line():
    print("-" * 64)

######################################################

my_ipv4_address = ipaddress.ip_address('192.168.0.1')
# my_ipv4_address = ipaddress.ip_address('1.0.0.2')

output_line()
print("my_ipv4_address = ", my_ipv4_address)
output_line()

# or, you can force an IPv4 or IPv6 address:
# print(ipaddress.IPv4Address(my_ipv4_address))

# print("type(my_ipv4_address) = ", type(my_ipv4_address))

# dir(object). List the names defined in the given object, i.e.,
# functions, classes and variables.
# print("dir(my_ipv4_address) = ", dir(my_ipv4_address))

# Output object as a string.
# print("str(my_ipv4_address) = ", str(my_ipv4_address))
# print("my_ipv4_address.__str__() = ", my_ipv4_address.__str__())

# Test the type of IP address.

"""
print("my_ipv4_address.is_loopback = ", my_ipv4_address.is_loopback)
print("my_ipv4_address.is_global = ", my_ipv4_address.is_global)
print("my_ipv4_address.is_private = ", my_ipv4_address.is_private)
"""

# Get printable representation of an object. Tries to give a string
# that would give the same result if run by eval().
# print("repr(my_ipv4_address) = ", repr(my_ipv4_address))
# print("my_ipv4_address.__repr__() = ", my_ipv4_address.__repr__())
# print("type(my_ipv4_address.__repr__()) = ", type(my_ipv4_address.__repr__()))

# eval example:
# s = "my_ipv4_address.is_private"
# print(s, " = ", eval(s))

# Get the IP address in different string formats.

'''
print("int(my_ipv4_address) = ", int(my_ipv4_address))
print("bin(int(my_ipv4_address)) = ", bin(int(my_ipv4_address))) # creates a string
print("hex(int(my_ipv4_address)) = ", hex(int(my_ipv4_address))) # creates a string
'''

# Do some simple math with IP addresses.
# for n in range(1, 10):
#     print(ipaddress.ip_address("192.168.1.250") + n)

# Create IP address directly from bytes objects.
# my_address_bytes = b'\xc0\xa8\x00\x01'
# print(my_address_bytes)
# print("ipaddress.ip_address(my_address_bytes) = ", ipaddress.ip_address(my_address_bytes))

# Created directly from integer objects.
# my_address_int = 3232235521
# print(my_address_int)
# print("ipaddress.ip_address(my_address_int) = ", ipaddress.ip_address(my_address_int))

######################################################
# IP Network objects (The host bits must all be zero).
######################################################

"""
my_ipv4_network = ipaddress.ip_network('192.168.1.0/24')
# my_ipv4_network = ipaddress.ip_network('192.168.1.0/31')
output_line()
print("my_ipv4_network = ", my_ipv4_network)
output_line()
"""

"""
my_ipv4_network = ipaddress.ip_network('192.168.1.0/24')
print("type(my_ipv4_network) = ", type(my_ipv4_network))
print("my_ipv4_network.num_addresses = ", my_ipv4_network.num_addresses)
print("my_ipv4_network.netmask = ", my_ipv4_network.netmask)
print("bin(int(my_ipv4_network.netmask)) = ", bin(int(my_ipv4_network.netmask)))
print("my_ipv4_network.is_private = ", my_ipv4_network.is_private)
# also .is_global, .is_multicast.
print("my_ipv4_network.broadcast_address = ", my_ipv4_network.broadcast_address)
"""

"""
# Iterate over some defined subnets.
my_ipv4_network = ipaddress.ip_network('192.168.1.0/24')
for net in my_ipv4_network.subnets(prefixlen_diff=4): # extend subnet by 4 bits
    print(net)

print("*"*12)

for net in my_ipv4_network.subnets(new_prefix=26): # extend subnet by 2 bits
    print(net)
    print(bin(int(net.network_address)))    
    print(bin(int(net.netmask)))
"""

"""
# Create a list of the subnets formed above.
my_ipv4_network = ipaddress.ip_network('192.168.1.0/24')
print(list(my_ipv4_network.subnets(new_prefix=26)))
"""

"""
# We can use .hosts() as a list of address objects in the network
# (remove un-assignable addresses)
my_ipv4_network = ipaddress.ip_network('192.168.1.0/24')
for a in my_ipv4_network.hosts():
    print(a)
"""

# We can also index the network addresses inside a network.
# print(my_ipv4_network[0])
# print(my_ipv4_network[1])
# print(my_ipv4_network[2])
# print(list(my_ipv4_network)[0:8])

######################################################
# Is HOST in NETWORK?

"""
HOST_LIST = [
    '10.0.30.1',
    '10.0.40.1'
]

NETWORK = '10.0.0.0/255.255.224.0'
my_network = ipaddress.ip_network(NETWORK)

for host in HOST_LIST:
    if ipaddress.ip_address(host) in my_network:
        print("Host {} is in {}".format(host, NETWORK))
    else:
        print("Host {} is not in {}".format(host, NETWORK))

"""

######################################################
# IP interface objects.
######################################################

# Is a subclass of IP address object, so it inherits all the
# attributes from that class. It uses the same constructor format
# except that arbitrary host bits can be set.

"""
interface = ipaddress.IPv4Interface('192.168.1.22/24')
print("interface = ", interface)
output_line()

print("interface.ip = ", interface.ip)
print("interface.network = ", interface.network)
print("interface.with_prefixlen = ", interface.with_prefixlen)
print("interface.with_netmask = ", interface.with_netmask)
"""

######################################################
# Other ipaddress module functions
######################################################

# Convert an integer ip address into a bytes object in big-endian
# order (i.e., network byte order).

# address_int = int(ipaddress.ip_address("192.168.1.100"))
# print(ipaddress.v4_int_to_packed(address_int))

######################################################

output_line()

######################################################

