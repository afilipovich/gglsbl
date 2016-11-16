gglsbl
======

Python client library for Google Safe Browsing Update API v4.

The code was developed according to official
[Developers Guide](https://developers.google.com/safe-browsing/v4/update-api), however this is not a reference implementation.

Quick start
-----------

###### Get Google API key
Instructions to procure API key can be found [here](https://developers.google.com/safe-browsing/v4/get-started).
Please note that v3/v4 key is different from v2.2 API. API v3 key may work with current API v4.

###### Install the library

```
    python setup.py install
```

###### To sync local hash prefix cache

```python
    from gglsbl import SafeBrowsingList
    sbl = SafeBrowsingList('API KEY GOES HERE')
    sbl.update_hash_prefix_cache()
```

###### URL lookup

```python
    from gglsbl import SafeBrowsingList
    sbl = SafeBrowsingList('API KEY GOES HERE')
    sbl.lookup_url('http://github.com/')
```

CLI Tool
--------
*bin/gglsbl_client.py* can be used for a quick check or as a code example.

###### To immediately sync local cache with Safe Browsing API. 
```
    gglsbl_client.py --api-key 'API KEY GOES HERE' --onetime
```
_Please mind [Request Frequency policy](https://developers.google.com/safe-browsing/v4/request-frequency) if you are going to use this command for more than a one-time test._

###### To look up URL
```
    gglsbl_client.py --api-key 'API KEY GOES HERE' --check-url http://github.com/
```

###### Fore more options please see
```
    gglsbl_client.py --help
```

Running on Python3
------------
Current version of library is intended to be compatible with both python2.7 and python3.

If you prefer to use older v3 version of Safe Browsing API there is a [python3 port](https://github.com/Stefan-Code/gglsbl3) of the legacy version made by [Stefan](https://github.com/Stefan-Code).
