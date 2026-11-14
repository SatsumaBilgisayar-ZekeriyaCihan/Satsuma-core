"""Compatibility status only; external baseline management has been retired."""
def status(*args,**kwargs):
    return {"status":"REMOVED","installed":False,"reason":"Satsuma application image verification replaces host baseline checks"}
