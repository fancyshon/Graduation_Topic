# Project

## 架構
	Client <-> (TCP) NXP (TCP) <-> Server
### Client <-> (TCP) NXP
	Client IP: 10.1.1.2
	Client Port: 54321
	
	NXP IP: 10.1.1.4
	NXP Port: 54321
### NXP (TCP) <-> Server
	NXP IP: 10.1.1.4
	NXP Port: 12345
	
	Client IP: 10.1.1.2
	Client Port: 12345


## Packet Control Byte:
### First byte in payload
	00: data packet
	01: ECIES public key packet
	02: File Request packet
	03: generate key
	04: ECIES R packet
	05: Request File system packet
	06: Response File system packet
	09: Mac Error


### File information packet format:
	file name \n
	file size \n

### File System packet format:
	number of files(first byte)
	file name \n
	file size \n
	
