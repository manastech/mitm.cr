> [!IMPORTANT]
> This library is no longer supported or updated by the Manas.Tech,
> therefore we have archived the repository.
> 
> The contents are still available readonly and continue to work as a
> [shards](https://github.com/crystal-lang/shards/) dependency.
>
> If you wish to continue development yourself, we recommend you fork it.
> We can also arrange to transfer ownership.
>
> If you have further questions, please reach out on https://forum.crystal-lang.org
> or crystal@manas.tech

# mitm

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
