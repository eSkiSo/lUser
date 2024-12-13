# lUser
_LDAP User client written in GO_

![Screenshot](/screenshot.png)

## Use

> luser [optional argument] <user|number|email|sid> <optional search if -gsl or -gs>

### Search User
> luser <user|number|email>

### Search User in both server
> luser -a <user|partial user|number|email|partial name>

### Search User with Groups
> luser -g <user|number|email> - Separated by  |
> luser -gl <user|number|email> - Separated by new line

### Search User with search/filter of group
> luser -gs <user|number|email> <text to search> - Separated by  |
> luser -gsl <user|number|email> <text to search>  - Separated by new line

### Search Groups / List Members
> luser -G <group name>

### Encrypt password to use on configs
> luser -e <password to encrypt>

## Install

Copy binary into a path that is defined in $PATH (/usr/bin/local in linux or mac for example)
Fill **luser_config.yml** with configurations and copy to user root folder with the name **.luser_config.yml**

## Compilation

```
GOOS=windows GOARCH=amd64 go build -o bin/windows/luser.exe luser.go
GOOS=linux GOARCH=amd64 go build -o bin/linux/luser luser.go
GOOS=darwin GOARCH=amd64 go build -o bin/macos/luser luser.go
```


## Maybe TODO

* Remove password lock: delete pwdAccountLockedTime?

