# ACS Authentication plugin for Grails

Add support to [Microsoft ACS](http://en.wikipedia.org/wiki/Access_Control_Service) (Access Control Service) to Grails Spring security

## Status

This plugin is not production ready at all at this time:

* No documentation
* Poor signature checking
* No central releases

## Requirements

* Grails 2.3+ (not tested with previous versions)
* Spring security core 2.0+

## How to install

```
repositories{
	mavenRepo 'https://s3-eu-west-1.amazonaws.com/grails-acs-security/release/'
}
...
plugins {
	compile ':acs-security:0.11.1'
}
```

## License

Apache 2.0
