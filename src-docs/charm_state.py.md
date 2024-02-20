<!-- markdownlint-disable -->

<a href="../src/charm_state.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `charm_state.py`
State of the Charm. 

**Global Variables**
---------------
- **VAULT_FILE_MISSING**
- **SQUID_DIGEST_AUTH_PROGRAM**
- **SQUID_BASIC_AUTH_PROGRAM**


---

## <kbd>class</kbd> `AuthenticationTypeEnum`
Represent the authentication type supported. 



**Attributes:**
 
 - <b>`BASIC`</b>:  Basic authentication in htpasswd file. 
 - <b>`DIGEST`</b>:  Digest authentication in htdigest file. 





---

## <kbd>class</kbd> `CharmState`
State of the Charm. 



**Attributes:**
 
 - <b>`squid_auth_config`</b>:  An instance of SquidAuthConfig. 
 - <b>`squid_tools_path`</b>:  A validated path for Squid tools folder. 




---

<a href="../src/charm_state.py#L77"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>classmethod</kbd> `from_charm`

```python
from_charm(charm: CharmBase) → CharmState
```

Initialize a new instance of the CharmState class from the associated charm. 



**Args:**
 
 - <b>`charm`</b>:  The charm instance associated with this state. 

Returns: An instance of the CharmState object. 



**Raises:**
 
 - <b>`CharmConfigInvalidError`</b>:  For any validation error in the charm config data. 

---

<a href="../src/charm_state.py#L140"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `get_as_relation_data`

```python
get_as_relation_data() → list[dict[str, Any]]
```

Format the CharmState data as a dictionary for relation data. 

Returns: A dictionary with CharmState data. 

---

<a href="../src/charm_state.py#L121"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `get_auth_vault`

```python
get_auth_vault() → HtdigestFile | HtpasswdFile
```

Load the vault file in an HtdigestFile or HtpasswdFile instance. 

Returns: An instance of HtdigestFile or HtpasswdFile. 



**Raises:**
 
 - <b>`SquidPathNotFoundError`</b>:  If the digest file is missing. 

---

<a href="../src/charm_state.py#L114"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `vault_file_exists`

```python
vault_file_exists() → bool
```

Check if the vault file exists. 

Returns: Whether the vault file exists. 


---

## <kbd>class</kbd> `SquidAuthConfig`
Represent the Htfile Auth helper configuration values. 



**Attributes:**
 
 - <b>`children_max`</b>:  children_max config. 
 - <b>`children_startup`</b>:  children_startup config. 
 - <b>`children_idle`</b>:  children_idle config. 
 - <b>`vault_filepath`</b>:  vault_filepath config. 
 - <b>`nonce_garbage_interval`</b>:  nonce_garbage_interval config. 
 - <b>`nonce_max_duration`</b>:  nonce_max_duration config. 
 - <b>`nonce_max_count`</b>:  nonce_max_count config. 
 - <b>`realm`</b>:  realm config. 
 - <b>`authentication_type`</b>:  One of digest or basic AuthenticationTypeEnum. 


---

#### <kbd>property</kbd> model_extra

Get extra fields set during validation. 



**Returns:**
  A dictionary of extra fields, or `None` if `config.extra` is not set to `"allow"`. 

---

#### <kbd>property</kbd> model_fields_set

Returns the set of fields that have been explicitly set on this model instance. 



**Returns:**
  A set of strings representing the fields that have been set,  i.e. that were not filled from defaults. 




