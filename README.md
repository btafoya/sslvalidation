btafoya/sslvalidation
==================

Small utility library that downloads and returns ssl certificate information from a running web server.


Installation
------------

Install the latest version with:

```bash
$ composer require btafoya/sslvalidation
```


Requirements
------------

* PHP 5.5.6+ is required but using the latest version of PHP is highly recommended.


Basic usage
-----------

# `btafoya\sslValidation\sslValidation`

- `sslValidation::getSSLInformation($domain, $port)`: Returns array data


## Example

```php
$certInfo = btafoya\sslValidation\sslValidation::getSSLInformation("freessltest.com", "443");
```


License
-------

btafoya/sslvalidation is licensed under the MIT License, see the LICENSE file for details.
