
# antivirus-scanner

[![Build Status](https://travis-ci.org/hmrc/antivirus-scanner.svg?branch=master)](https://travis-ci.org/hmrc/antivirus-scanner) [ ![Download](https://api.bintray.com/packages/hmrc/releases/antivirus-scanner/images/download.svg) ](https://bintray.com/hmrc/releases/antivirus-scanner/_latestVersion)

## Summary

This service provides a REST API for ClamAV

The max file size is configurable (10 Mb default)


## Local Installation

This requires [ClamAV](http://www.clamav.net/) to be installed

For Macs

```brew install clamav```

You can find a slightly longer explaination [here](https://gist.github.com/paulspringett/8802240)

You will also need to add the following alias to your /etc/hosts

```127.0.0.1       avscan```

### Antivirus Scanning Exclusions

This repository includes the EICAR standard antivirus test file. To prevent this file from being deleted you'll need to exclude this repo's `target` and `test/resources` directories from AV scanning. In Sophos Anti-Virus this is done as shown in the screenshot:

![Sophos Anti-Virus Preferences Screenshot](doc/sophos-av-exclusions.png?raw=true)

### License

This code is open source software licensed under the [Apache 2.0 License]("http://www.apache.org/licenses/LICENSE-2.0.html").
