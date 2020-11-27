# mitm

TODO: Write a description here

## Installation

TODO: Write installation instructions here

## Usage

### Create CA certificate

1. Create directory for certificates
```
$ mkdir certs
```

2. Generate a private key file
```
$ openssl genrsa -out certs/ca.key
```

3. Generate a self signed certificate
```
$ openssl req -x509 -new -key certs/ca.key -days 50000 -out certs/ca.crt -subj "/CN=mitm.cr"
```

4. Install the generated certificate in your browser


### Run the standalone proxy server
```
$ crystal src/main.cr
```

The proxy server will start and listen on port 8080

## Development

TODO: Write development instructions here

## Contributing

1. Fork it (<https://github.com/your-github-user/mitm.cr/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [your-name-here](https://github.com/your-github-user) - creator and maintainer
