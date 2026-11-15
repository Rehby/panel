"""Choose typed provisioning or keep an explicitly imported configuration."""
import provision

def apply(s):
    if s.get('simple_engine') is True and s['protocol'] in provision.PROTOCOLS:
        return provision.prepare(s)
    return s
