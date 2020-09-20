#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from struct import unpack
import json
import aioblescan as aios

# Tilt Hydrometer aioblescan plugin
# Forked from https://github.com/baronbrew/aioblescan

# Tilt format: Apple iBeacon identifier portion (4c000215) + Tilt specific uuid preamble (a495)
TILT = '4c000215a495'


class Tilt(object):
    """
    Class defining the content of a Tilt advertisement
    """

    def decode(self, packet):
        data = {}
        raw_data = packet.retrieve('Payload for mfg_specific_data')
        if raw_data:
            pckt = raw_data[0].val
            payload = raw_data[0].val.hex()
            mfg_id = payload[0:12]
            rssi = packet.retrieve('rssi')
            mac = packet.retrieve("peer")
            if mfg_id == TILT:
                data['uuid'] = payload[8:40]
                data['major'] = unpack('>H', pckt[20:22])[0]  # Temp, Deg. F
                data['minor'] = unpack('>H', pckt[22:24])[0]  # SG x1000
                data['tx_power'] = unpack('>b', pckt[24:25])[0] # Operation Codes
                data['rssi'] = rssi[-1].val
                data['mac'] = mac[-1].val
                return json.dumps(data)
