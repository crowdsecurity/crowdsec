# Bouncers & Machines management

Crowdsec is composed of different components that communicate via a local API.
To access this API, the various components (crowdsec agent, cscli and bouncers) need to be authenticated.

!!! info
        This documentation should be relevant mostly for administrators that would like to setup distributed architectures. Single machine setup users can likely skip this part.


There are two kind of access to the local api :

 - `machines` : it's a login/password authentication used by {{v1X.cli.name}} and {{v1X.crowdsec.name}}, this one allows to post, get and delete decisions and alerts.
 - `bouncers` : it's a token authentication used by {{v1X.bouncers.htmlname}} to query the decisions, and only allows to perform get on decisions and alerts.

## Bouncers authentication

!!! warning
        The `cscli bouncers` command interacts directly with the database (bouncers add and delete are not implemented in the API), and thus it must have the correct database configuration.

```bash
$ sudo cscli bouncers list
```


You can view the registered bouncers with `list`, as well as add or delete them :

```bash
$ sudo cscli bouncers add mybouncersname
Api key for 'mybouncersname':

   23........b5a0c

Please keep this key since will not be able to retrive it!
$ sudo cscli bouncers delete mybouncersname
```

The API KEY must be kept and given to the {{v1X.bouncers.htmlname}}.

<details>
  <summary>cscli bouncers example</summary>
```bash
$ sudo cscli bouncers add mybouncersname
Api key for 'mybouncersname':

   23........b5a0c

Please keep this key since will not be able to retrive it!
$ sudo cscli bouncers list              
-----------------------------------------------------------------------------
 NAME            IP ADDRESS  VALID  LAST API PULL              TYPE  VERSION 
-----------------------------------------------------------------------------
 mybouncersname              ✔️     2020-11-01T11:45:05+01:00                
-----------------------------------------------------------------------------
$ sudo cscli bouncers add  jlkqweq
Api key for 'jlkqweq':

   a7........efdc9c

Please keep this key since will not be able to retrive it!
$ sudo cscli bouncers delete mybouncersname
$ sudo cscli bouncers list                 
----------------------------------------------------------------------
 NAME     IP ADDRESS  VALID  LAST API PULL              TYPE  VERSION 
----------------------------------------------------------------------
 jlkqweq              ✔️     2020-11-01T11:49:32+01:00                
----------------------------------------------------------------------
```

</details>

## Machines authentication

!!! warning
        The `cscli machines` command interacts directly with the database (machines add and delete are not implemented in the API), and thus it must have the correct database configuration.

```bash
$ cscli machines list
```

You can view the registered machines with `list`, as well as add or delete them :

```bash
$ sudo cscli machines add mytestmachine -a
INFO[0004] Machine 'mytestmachine' created successfully       
INFO[0004] API credentials dumped to '/etc/crowdsec/local_api_credentials.yaml' 
$ sudo cscli machines delete 82929df7ee394b73b81252fe3b4e5020
```


<details>
  <summary>cscli machines example</summary>

```bash
$ sudo cscli machines list
----------------------------------------------------------------------------------------------------------------------------------
 NAME                              IP ADDRESS  LAST UPDATE                STATUS  VERSION                                         
----------------------------------------------------------------------------------------------------------------------------------
 82929df7ee394b73b81252fe3b4e5020  127.0.0.1   2020-10-31T14:06:32+01:00  ✔️      v0.3.6-3d6ce33908409f2a830af6551a7f5e37f2a4728f 
----------------------------------------------------------------------------------------------------------------------------------
$ sudo cscli machines add -m mytestmachine -a
INFO[0004] Machine 'mytestmachine' created successfully       
INFO[0004] API credentials dumped to '/etc/crowdsec/local_api_credentials.yaml' 
$ sudo cscli machines list      
----------------------------------------------------------------------------------------------------------------------------------
 NAME                              IP ADDRESS  LAST UPDATE                STATUS  VERSION                                         
----------------------------------------------------------------------------------------------------------------------------------
 82929df7ee394b73b81252fe3b4e5020  127.0.0.1   2020-10-31T14:06:32+01:00  ✔️      v0.3.6-3d6ce33908409f2a830af6551a7f5e37f2a4728f 
 mytestmachine                     127.0.0.1   2020-11-01T11:37:19+01:00  ✔️      v0.3.6-6a18458badf8ae5fed8d5f1bb96fc7a59c96163c 
----------------------------------------------------------------------------------------------------------------------------------
$ sudo cscli machines delete -m 82929df7ee394b73b81252fe3b4e5020
$ sudo cscli machines list                                      
---------------------------------------------------------------------------------------------------------
 NAME     IP ADDRESS  LAST UPDATE                STATUS  VERSION                                         
---------------------------------------------------------------------------------------------------------
 mytestmachine  127.0.0.1   2020-11-01T11:37:19+01:00  ✔️      v0.3.6-6a18458badf8ae5fed8d5f1bb96fc7a59c96163c 
---------------------------------------------------------------------------------------------------------
```

</details>
