# run : uvicorn server:app --reload

from typing import Union

from fastapi import FastAPI
import time

relay_timeout = 5*60 # secondes

t0 = time.time()
app = FastAPI()


# relay : 
#     t  : int, dernier contact
#     ip : str
#     key : str

relays = set()

def purge_relays():
    global relays
    t_timed_out = time.time() - t0 - relay_timeout
    relays = set( (t,key,ip) for (t,key,ip) in relays if t>t_timed_out )

def add_relay(ip:str, key:str):
    t = time.time() - t0
    relays.add((t,key,ip))

@app.get("/")
def read_root():
    # on envoit le temps restant avant timeout
    purge_relays()
    return [((time.time() - t0) - t, key,ip) for (t,key,ip) in relays]


@app.get("/add/{ip}/{key}")
def read_item(ip: str, key: str):
    add_relay(ip, key)