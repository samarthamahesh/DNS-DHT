# Distributed System (Spring 2022)

### Domain Name System (DNS) using Distributed Hash Table (DHT)

_Samartha S M (2018101094), Aditya Gupta (2018102010), Amey Kudari (2018101046)_

---

### Project overview

We are using Distributed Hash Table (DHT) to implement the mappings of domain names to IP addresses for Domain Name System (DNS). The current Domain Name System (DNS) follows a hierarchical tree structure. Several recent efforts proposed to re-implement DNS as a peer-to-peer network with a flat structure that uses Distributed Hash Table (DHT) to improve the system availability.

### How to run?

```bash
$ sudo python3 dns_dht.py --num_nodes <num_dht_nodes> --data_path <domains-ip_path>
```

The above command will activate DNS server and bootstrap the DHT nodes to import the domain-IP data

```bash
$ dig <domain_name> @127.0.0.1
```

This command will send a DNS request through default port 53 to local DNS server which is running on localhost (127.0.0.1) and get back the DNS response with corresponding IP address for domain name

### Example output

_google.com (142.250.205.238)_

![google.com](C:\Users\Samartha S M\Desktop\unnamed.png)