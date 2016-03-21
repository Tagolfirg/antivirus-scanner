
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

Please note. To run the build locally you need to disable any other virus checker you have installed on your machine

### License

This code is open source software licensed under the [Apache 2.0 License]("http://www.apache.org/licenses/LICENSE-2.0.html").
    