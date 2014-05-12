# ACS Authentication plugin for Grails

Add support to [Microsoft ACS](http://en.wikipedia.org/wiki/Access_Control_Service) (Access Control Service) to Grails Spring security

## Status

This plugin is not production ready at all at this time:

* No documentation
* No signature verification !!
* No central releases

## Requirements

* Grails 2.3+ (not tested with previous versions)
* Spring security core 2.0+

## How to install

```
repositories{
	mavenRepo 'http://repository-cblonde.forge.cloudbees.com/snapshot'	
}
...
plugins {
	compile ':acs-security:0.3-SNAPSHOT'
}
```

## License

Apache 2.0
