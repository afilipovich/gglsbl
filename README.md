gglsbl
======

Client library for Google Safe Browsing API

Disclaimer
----------
While the code was developed according to official
[Developers Guide](https://developers.google.com/safe-browsing/developers_guide_v3)
this is **not** a reference implementation. You also may want to check
[Acceptable Use Policy](https://developers.google.com/safe-browsing/developers_guide_v3#AcceptableUsage)
for Safe Browsing API

Quick start
-----------

###### Get Google API key
Instructions can be found [here](https://developers.google.com/safe-browsing/lookup_guide#GettingStarted)

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

*On a first run it may take up to several hours to complete the sync*

###### URL lookup

```python
    from gglsbl import SafeBrowsingList
    sbl = SafeBrowsingList('API KEY GOES HERE')
    sbl.lookup_url('http://github.com/')
```

CLI Tool
--------
Please see gglsbl_client.py which can be used to sync lists data in the background
and perform single URL lookups
