from asyncio.windows_events import NULL
import os
import logging
import datetime
import json
from mqtt import connect_mqtt

from RestrictedPython import (
    compile_restricted_exec,
    limited_builtins,
    safe_builtins,
    utility_builtins,
)
from RestrictedPython.Eval import default_guarded_getitem
from RestrictedPython.Guards import (
    full_write_guard,
    guarded_iter_unpack_sequence,
    guarded_unpack_sequence,
)

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s  %(name)s - %(message)s')

logger = logging.getLogger('standalone-main')

mqtt_host = os.getenv('MQTT_HOST', '127.0.0.1')
mqtt_port = int(os.getenv('MQTT_PORT', 1883))
mqtt_user = os.getenv('MQTT_USER', '')
mqtt_password = os.getenv('MQTT_PASSWORD', '')

class CallMock():
    def __init__(self, client):
        self.client = client

    def call(self, service, type, data, param4):
        self.client.publish(data['topic'], data['payload'], data['qos'], data['retain'])

class HassMock():
    def initClient(self, client):
        self.client = client
        self.services = CallMock(client)
        

hassMock = HassMock()

def execute(filename, source, data=None):
    """Execute Python source."""

    compiled = compile_restricted_exec(source, filename=filename)

    if compiled.errors:
        logger.error("Error loading script %s: %s", filename, ", ".join(compiled.errors))
        return

    if compiled.warnings:
        logger.warning("Warning loading script %s: %s", filename, ", ".join(compiled.warnings))

    def protected_getattr(obj, name, default=None):
        """Restricted method to get attributes."""
        if name.startswith("async_"):
            raise Exception("Not allowed to access async methods")

        return getattr(obj, name, default)

    extra_builtins = {
        "sorted": sorted,
        "min": min,
        "max": max,
        "sum": sum,
        "any": any,
        "all": all,
        "enumerate": enumerate,
    }
    builtins = safe_builtins.copy()
    builtins.update(utility_builtins)
    builtins.update(limited_builtins)
    builtins.update(extra_builtins)
    logger_discovery = logging.getLogger(f"{__name__}.{filename}")
    restricted_globals = {
        "__builtins__": builtins,
        "_getattr_": protected_getattr,
        "_write_": full_write_guard,
        "_getiter_": iter,
        "_getitem_": default_guarded_getitem,
        "_iter_unpack_sequence_": guarded_iter_unpack_sequence,
        "_unpack_sequence_": guarded_unpack_sequence,
        "hass": hassMock,
        "data": data or {},
        "logger": logger_discovery,
    }

    try:
        logger.info("Executing %s: %s", filename, data)
        # pylint: disable=exec-used
        exec(compiled.code, restricted_globals)
    except Exception as err:  # pylint: disable=broad-except
        logger.exception("Error executing script: %s", err)

def on_announce(client, userdata, msg):
    logger.info("MQTT Receive: {}, {}".format(msg.topic,msg.payload.decode()))
    data = json.loads(msg.payload.decode())
    filename = './python_scripts/shellies_discovery.py'

    with open(filename, encoding="utf8") as fil:
        source = fil.read()

    execute(filename, source, {
        "id": data['id'],
        "mac": data['mac'],
        "fw_ver": data['fw_ver'],
        "model": data['model'],
        "mode": data['mode'] if 'mode' in data else 'default',
        "host": data['ip'],
        "discovery_prefix": 'shelly'
    })

def on_connect(client, userdata, flags, rc):
    hassMock.initClient(client)
    client.message_callback_add('shellies/announce', on_announce)
    client.subscribe('shellies/announce')
    client.publish('shellies/command', 'announce')


connect_mqtt('ha-shellies-discovery', mqtt_user, mqtt_password, mqtt_host, on_connect, mqtt_port).loop_forever()