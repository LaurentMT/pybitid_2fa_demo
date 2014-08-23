# PyBitID

A python demo application of 2-Factor Authentication with the BitId protocol. 

The goal of this toy project is to illustrate how BitId can be used to implement 2FA in addition to a basic authentication system (by login/password).

Live demo: http://vps90685.ovh.net:8081/


## Python versions

Tested with Python 2.7.6 and 3.3.3


## Dependencies

Flask (http://flask.pocoo.org/) - A microframework for web development
```
pip install flask
```

PyBitId (https://github.com/LaurentMT/pybitid) - A python library for the BitId protocol
```
Gets the library from Github : https://github.com/LaurentMT/pybitid/archive/master.zip
Unzips the archive in a temp directory
python setup.py install
```


## Links
 - BitId protocol : https://github.com/bitid/bitid
 - PyBitId : https://github.com/LaurentMT/pybitid
 - Android wallet implementing BitId : https://github.com/bitid/bitcoin-wallet


## Author
Twitter: @LaurentMT


WORK IN PROGRESS !!! CONTRIBUTORS ARE WELCOME !

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
