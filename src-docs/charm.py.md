<!-- markdownlint-disable -->

<a href="../src/charm.py#L0"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

# <kbd>module</kbd> `charm.py`
A subordinate charm enabling support for digest authentication on Squid Reverseproxy charm. 

**Global Variables**
---------------
- **AUTH_HELPER_RELATION_NAME**
- **DIGEST_REALM**
- **EVENT_FAIL_RELATION_MISSING_MESSAGE**
- **STATUS_BLOCKED_RELATION_MISSING_MESSAGE**


---

## <kbd>class</kbd> `DigestSquidAuthHelperCharm`
A subordinate charm enabling support for digest auth on Squid Reverseproxy charm. 

<a href="../src/charm.py#L32"><img align="right" style="float:right;" src="https://img.shields.io/badge/-source-cccccc?style=flat-square"></a>

### <kbd>function</kbd> `__init__`

```python
__init__(*args)
```

Construct the charm. 



**Args:**
 
 - <b>`args`</b>:  Arguments passed to the CharmBase parent constructor. 


---

#### <kbd>property</kbd> app

Application that this unit is part of. 

---

#### <kbd>property</kbd> charm_dir

Root directory of the charm as it is running. 

---

#### <kbd>property</kbd> config

A mapping containing the charm's config and current values. 

---

#### <kbd>property</kbd> meta

Metadata of this charm. 

---

#### <kbd>property</kbd> model

Shortcut for more simple access the model. 

---

#### <kbd>property</kbd> unit

Unit that this execution is responsible for. 




