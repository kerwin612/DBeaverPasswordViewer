# DBeaverPasswordViewer
> A tool for viewing DBeaver Community Edition passwords  

**Usage:**
```bash
DBeaverPasswordViewer path_of_credentials-config.json[#name_of_connection] [iv] [key]
```

**example:** 
* List all connection configuration information
```bash
DBeaverPasswordViewer $DBEAVER_WORKSPACE/General/.dbeaver/credentials-config.json
```
* List configuration information for connection name ***test_connect***
```bash
DBeaverPasswordViewer $DBEAVER_WORKSPACE/General/.dbeaver/credentials-config.json#test_connect
```
