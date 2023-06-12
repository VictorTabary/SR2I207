# run : uvicorn server:app --reload --host 0.0.0.0 --port 80

from typing import Union

from fastapi import FastAPI
import time

relay_timeout = 5*60 # secondes
service_timeout = 30*60 # secondes

t0 = time.time()
app = FastAPI()

# relay : 
#     t  : int, dernier contact
#     key : str
#     ip : str

relays = set()

@app.get("/relays")
def get_relays():
    global relays

    # purge old relays
    t_timed_out = time.time() - t0 - relay_timeout
    relays = set( (t,key,ip) for (t,key,ip) in relays if t>t_timed_out )

    # on envoit le temps restant avant timeout
    return [((time.time() - t0) - t, key,ip) for (t,key,ip) in relays]

@app.get("/relays/add/{ip}/{key}")
def add_relay(ip: str, key: str):
     t = time.time() - t0
     relays.add((t,key,ip))


services = set()

@app.get("/services")
def get_services():
    global services

    # purge old services
    t_timed_out = time.time() - t0 - service_timeout
    services = set( (t,hash,key,ips) for (t,hash,key,ips) in services if t>t_timed_out )

    # on envoit le temps restant avant timeout
    return [((time.time() - t0) - t, hash,key,ips) for (t, hash,key,ips) in services]

@app.get("/services/add/{hash}/{key}/{ips}")
def add_service(hash:str,  key: str, ips: str):
     t = time.time() - t0
     services.add((t,hash,key,ips))