# crypt_mppe_key

Encrypt or decrypt a `MS-MPPE-Send-Key` or `MS-MPPE-Recv-Key` attribute of RADIUS message.  

### Usage

    crypt_mppe_key.py [-e] [-s|h|b] shared-key clear-key authenticator salt
    crypt_mppe_key.py -d [-s|h|b] shared-key ms-mppe-key authenticator

### Options

    -e (default)
        Encrypt a clear key for a MS-MPPE-Send-Key/MS-MPPE-Recv-Key attribute
    -d
        Decrypt a MS-MPPE-Send-Key/MS-MPPE-Recv-Key attribute for a clear key

### Parameters

    shared-key   : the shared secret used by the RADIUS server/clients
    clear-key    : the clear key to encrypt
    ms-mppe-key  : the MS-MPPE-Send-Key/MS-MPPE-Recv-Key attribute to decrypt
    authenticator: the authenticator attribute of previous RADIUS (Request) message
    salt         : the salt (2 bytes) used to encrypt the clear key

`shared-key` has to be a simple (ASCII) text.  
`clear-key`, `ms-mppe-key`, `authenticator` and `salt` have to be hex strings (the digit sequence can be splited with colon signs).  

### Output switchs

    -s (default)
        hex string with 2-digit sequence splited with colon signs
    -h
        full hex string
    -b
        binary data

### Examples

    $ crypt_mppe_key.py -e secret 01:02:03:04:05:06:07:08 101112131415161718191a1b1c1d1e1f 8000
    80:00:b0:63:4f:72:4f:ae:13:44:8d:f0:02:35:e3:de:6c:0a

    $ crypt_mppe_key.py -d secret 80:00:b0:63:4f:72:4f:ae:13:44:8d:f0:02:35:e3:de:6c:0a 101112131415161718191a1b1c1d1e1f
    01:02:03:04:05:06:07:08

### Python module

`crypt_mppe_key` can be used as a Python module:  

```python
from crypt_mppe_key import mppe_encrypt,mppe_decrypt
```
