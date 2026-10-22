from flask import Flask, render_template, request, send_from_directory, Response, jsonify, redirect, abort, session
import RPi.GPIO as GPIO
from datetime import datetime
import logging
import sys
import threading
import requests
import os
import time
import json
import math
import serial
import cv2
import jdatetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import subprocess
import signal
from urllib.parse import urlparse

from local_secrets import load_secret
from passkeys import Passkeys, PasskeyError, LoginGate, DEVICE_COOKIE, DEVICE_TTL

# =======================
# CONFIGURATION
# =======================
base_dir = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(base_dir, 'logs')

app = Flask(__name__)

# Security configuration - a random key per install, see local_secrets.py
app.config['SECRET_KEY'] = load_secret('smarthome')
# Cookies only travel on requests that start on this site. Without this a
# page elsewhere could make a logged-in browser POST /MainDoorToggle.
app.config.update(SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_HTTPONLY=True,
                  REMEMBER_COOKIE_SAMESITE='Lax', REMEMBER_COOKIE_HTTPONLY=True)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Domain the upload and firmware servers are published under (install.sh sets it)
BASE_DOMAIN = os.environ.get('SMARTHOME_DOMAIN', 'turingco.ir')

# Fingerprint login is bound to one address. Taken from configuration and
# never from the Host header, which whoever sends the request controls.
PASSKEY_RP_ID = os.environ.get('SMARTHOME_PASSKEY_RP_ID', f'home.{BASE_DOMAIN}')
PASSKEY_ORIGINS = [o.strip() for o in os.environ.get(
    'SMARTHOME_PASSKEY_ORIGINS', f'https://{PASSKEY_RP_ID}').split(',') if o.strip()]

# Simple user database (in memory)
# To add more users, add entries like: 'username': bcrypt.generate_password_hash('password').decode('utf-8')
users_db = {
    'parsa': bcrypt.generate_password_hash('13691113..').decode('utf-8'),
    'family': bcrypt.generate_password_hash('6055608..').decode('utf-8')
}


# User class
class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in users_db:
        return User(user_id)
    return None

# Configure logging
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
logger = logging.getLogger(__name__)

passkeys = Passkeys(os.path.join(base_dir, 'instance', 'passkeys.db'),
                    PASSKEY_RP_ID, PASSKEY_ORIGINS, 'Parsa Home', app.config['SECRET_KEY'])
login_gate = LoginGate()
if not passkeys.available:
    logger.warning("Fingerprint login is off: install python3-cryptography to enable it")

@app.before_request
def same_origin_posts_only():
    """Refuse state-changing requests sent from another site's page."""
    if request.method != 'POST':
        return None
    origin = request.headers.get('Origin')
    if origin and origin != 'null' and urlparse(origin).netloc != request.host:
        logger.warning(f"Blocked cross-site POST to {request.path} from {origin}")
        abort(403)
    return None

def client_ip():
    # Behind Caddy every request comes from 127.0.0.1; the visitor is in
    # X-Forwarded-For, which only a local proxy is trusted to set
    if request.remote_addr in ('127.0.0.1', '::1'):
        fwd = request.headers.get('X-Forwarded-For', '')
        if fwd:
            return fwd.split(',')[-1].strip()
    return request.remote_addr or ''

# =======================
# GLOBAL STATE VARIABLES
# =======================
current_mode = None
light_states = {}

# Upload server control
upload_server_process = None
upload_server_enabled = False

ac_split_state = {
    'running': False,
    'temperature': 23
}

# =======================
# GPIO CONFIGURATION
# =======================
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

# GPIO Pin Mapping
pinToType = {
    "Cooler_Pump": 11,
    "Hidden_Light": 0,
    "Living_Room_Chandelier": 8,
    "Living_Room_Halogen_Light": 17,
    "Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light": 24,
    "Double_Hallway_Linear_Light": 25,
    "Island_Top_Light": 5,
    "Kitchen_Ceiling_Light": 20,
    "Middle_Square_Living_Room_Light": 22,
    "Entryway_Light": 16,
    "Dinner_Room_Chandelier": 10,
    "Decorative_Dinner_Room_Wall_Linear_Light": 7,
    "Light_Receiver_1": 19,
    "Light_Dance_Light_Receiver": 1,
    "Light_Receiver_2": 12,
    "Behind_Stove_Hidden_Light": 13,
    "Double_Living_Room_Wall_Linear_Light": 27,
    "Fan_Between_Channels_Switch": 4,
    "Package_Electricity": 9,
    "Bar_Hidden_Light_Switch": 3,
    "TV_Hidden_Light": 6,
    "Parking_Remote": 26,
    "CoolerPower": 21,
    "Main_Door": 2,
    "Without_Channel1": 14,
    "Without_Channel2": 15,
    "Without_Channel3": 18,
    "Without_Channel4": 23,
}

# All controllable lights
AllLights = [
    pinToType["Hidden_Light"],
    pinToType["Living_Room_Chandelier"],
    pinToType["Living_Room_Halogen_Light"],
    pinToType["Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light"],
    pinToType["Double_Hallway_Linear_Light"],
    pinToType["Island_Top_Light"],
    pinToType["Kitchen_Ceiling_Light"],
    pinToType["Middle_Square_Living_Room_Light"],
    pinToType["Entryway_Light"],
    pinToType["Dinner_Room_Chandelier"],
    pinToType["Decorative_Dinner_Room_Wall_Linear_Light"],
    pinToType["Light_Receiver_1"],
    pinToType["Light_Dance_Light_Receiver"],
    pinToType["Light_Receiver_2"],
    pinToType["Behind_Stove_Hidden_Light"],
    pinToType["Double_Living_Room_Wall_Linear_Light"],
    pinToType["Bar_Hidden_Light_Switch"],
    pinToType["TV_Hidden_Light"]
]

# How the lights are shown in the control panel, grouped by room
LIGHT_GROUPS = [
    ("Living Room", "fa-couch", [
        ("Living_Room_Chandelier", "Chandelier"),
        ("Living_Room_Halogen_Light", "Halogen"),
        ("Middle_Square_Living_Room_Light", "Center Square"),
        ("Double_Living_Room_Wall_Linear_Light", "Wall Linear"),
        ("TV_Hidden_Light", "TV Backlight"),
        ("Hidden_Light", "Hidden Light"),
    ]),
    ("Kitchen & Bar", "fa-mug-hot", [
        ("Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light", "Pendant & Café Bar"),
        ("Island_Top_Light", "Island"),
        ("Kitchen_Ceiling_Light", "Ceiling"),
        ("Behind_Stove_Hidden_Light", "Behind Stove"),
        ("Bar_Hidden_Light_Switch", "Bar Hidden"),
    ]),
    ("Dining", "fa-utensils", [
        ("Dinner_Room_Chandelier", "Chandelier"),
        ("Decorative_Dinner_Room_Wall_Linear_Light", "Wall Linear"),
    ]),
    ("Hall & Entry", "fa-door-open", [
        ("Entryway_Light", "Entryway"),
        ("Double_Hallway_Linear_Light", "Hallway Linear"),
    ]),
    ("Extras", "fa-star", [
        ("Light_Dance_Light_Receiver", "Dance Light"),
        ("Light_Receiver_1", "Receiver 1"),
        ("Light_Receiver_2", "Receiver 2"),
    ]),
]

# Initialize light states
for pin in AllLights:
    light_states[pin] = False

# Lighting Modes
TV_MODE = [
    pinToType["Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light"],
    pinToType["Behind_Stove_Hidden_Light"]
]

BREAKFAST_MODE = [
    pinToType["Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light"],
    pinToType["Island_Top_Light"],
    pinToType["Living_Room_Halogen_Light"],
    pinToType["Hidden_Light"]
]

LUNCH_MODE = [
    pinToType["Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light"],
    pinToType["Living_Room_Halogen_Light"],
    pinToType["Decorative_Dinner_Room_Wall_Linear_Light"],
    pinToType["Dinner_Room_Chandelier"],
    pinToType["Hidden_Light"]
]

DINNER_MODE = [
    pinToType["Bar_Hidden_Light_Switch"],
    pinToType["Island_Top_Light"],
    pinToType["Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light"],
    pinToType["Living_Room_Halogen_Light"],
    pinToType["Decorative_Dinner_Room_Wall_Linear_Light"],
    pinToType["Dinner_Room_Chandelier"],
    pinToType["Hidden_Light"]
]

RELAX_MODE = [
    pinToType["Living_Room_Halogen_Light"],
    pinToType["Bar_Hidden_Light_Switch"],
    pinToType["TV_Hidden_Light"],
    pinToType["Living_Room_Chandelier"],
    pinToType["Hidden_Light"],
]

NORMAL_NIGHT_MODE = [
    pinToType["Hidden_Light"],
    pinToType["Decorative_Dinner_Room_Wall_Linear_Light"],
    pinToType["Living_Room_Halogen_Light"],
    pinToType["Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light"],
    pinToType["Island_Top_Light"],
    pinToType["Entryway_Light"],
    pinToType["Bar_Hidden_Light_Switch"],
    pinToType["TV_Hidden_Light"]
]

NORMAL_DAY = [
    pinToType["Hidden_Light"],
    pinToType["Living_Room_Halogen_Light"]
]

MEETING_MODE = [
    pinToType["Hidden_Light"],
    pinToType["Living_Room_Chandelier"],
    pinToType["Living_Room_Halogen_Light"],
    pinToType["Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light"],
    pinToType["Double_Hallway_Linear_Light"],
    pinToType["Island_Top_Light"],
    pinToType["Kitchen_Ceiling_Light"],
    pinToType["Middle_Square_Living_Room_Light"],
    pinToType["Entryway_Light"],
    pinToType["Dinner_Room_Chandelier"],
    pinToType["Decorative_Dinner_Room_Wall_Linear_Light"],
    pinToType["Light_Receiver_1"],
    pinToType["Light_Dance_Light_Receiver"],
    pinToType["Light_Receiver_2"],
    pinToType["Behind_Stove_Hidden_Light"],
    pinToType["Double_Living_Room_Wall_Linear_Light"],
    pinToType["Bar_Hidden_Light_Switch"]
]

PARTY_MODE = [
    pinToType["Shoe_Rack_Light_and_Kitchen_Pendant_Light_and_Cafe_Bar_Light"],
    pinToType["TV_Hidden_Light"],
    pinToType["Double_Hallway_Linear_Light"],
    pinToType["Entryway_Light"],
    pinToType["Light_Dance_Light_Receiver"]
]

COOKING_MODE = [
    pinToType["Island_Top_Light"],
    pinToType["Kitchen_Ceiling_Light"],
    pinToType["Living_Room_Halogen_Light"],
    pinToType["Bar_Hidden_Light_Switch"],
    pinToType["TV_Hidden_Light"],
    pinToType["Living_Room_Chandelier"],
    pinToType["Hidden_Light"],
]

mode_arrays = {
    "TV_MODE": TV_MODE,
    "BREAKFAST_MODE": BREAKFAST_MODE,
    "LUNCH_MODE": LUNCH_MODE,
    "DINNER_MODE": DINNER_MODE,
    "RELAX_MODE": RELAX_MODE,
    "NORMAL_NIGHT_MODE": NORMAL_NIGHT_MODE,
    "NORMAL_DAY": NORMAL_DAY,
    "MEETING_MODE": MEETING_MODE,
    "PARTY_MODE": PARTY_MODE,
    "COOKING_MODE": COOKING_MODE
}

# Scene buttons in the control panel: (mode, label, icon)
SCENES = [
    ("NORMAL_DAY", "Day", "fa-sun"),
    ("BREAKFAST_MODE", "Breakfast", "fa-mug-hot"),
    ("COOKING_MODE", "Cooking", "fa-fire"),
    ("LUNCH_MODE", "Lunch", "fa-utensils"),
    ("RELAX_MODE", "Relax", "fa-spa"),
    ("TV_MODE", "TV", "fa-tv"),
    ("DINNER_MODE", "Dinner", "fa-wine-glass"),
    ("NORMAL_NIGHT_MODE", "Night", "fa-moon"),
    ("MEETING_MODE", "All Bright", "fa-lightbulb"),
    ("PARTY_MODE", "Party", "fa-champagne-glasses"),
]

# =======================
# IR TRANSMITTER CONFIG
# =======================
GPIO_PIN = 18
PWM_FREQUENCY = 38000
PWM_ON_TIME = 540e-6
PWM_OFF_TIME_LONG = 3 * PWM_ON_TIME
PWM_OFF_TIME_SHORT = PWM_ON_TIME
PREAMBLE_ON_TIME = 6.1e-3
PREAMBLE_OFF_TIME = 7.388e-3
CLOSE_ON_TIME = 532e-6
CLOSE_OFF_TIME = 7.39e-3

# =======================
# IR TRANSMITTER FUNCTIONS
# =======================
# NOTE: these only time the frame - nothing here drives GPIO_PIN yet, so the
# split AC does not actually receive anything. A 38 kHz carrier needs
# hardware timing (pigpio waves or the kernel's gpio-ir-tx), not time.sleep().
def send_logic_1():
    time.sleep(PWM_ON_TIME)
    time.sleep(PWM_OFF_TIME_LONG)

def send_logic_0():
    time.sleep(PWM_ON_TIME)
    time.sleep(PWM_OFF_TIME_SHORT)

def preamble():
    time.sleep(PREAMBLE_ON_TIME)
    time.sleep(PREAMBLE_OFF_TIME)

def close():
    time.sleep(CLOSE_ON_TIME)
    time.sleep(CLOSE_OFF_TIME)
    time.sleep(CLOSE_ON_TIME)

def send_byte_array(byte_array):
    try:
        preamble()
        for byte in byte_array:
            for bit in range(8):
                if byte & (1 << (7 - bit)):
                    send_logic_1()
                else:
                    send_logic_0()
        close()
    except KeyboardInterrupt:
        time.sleep(CLOSE_ON_TIME)

def turnOnAirconditionerSplit():
    byte_array = [0xFF, 0x00, 0xFF, 0x00, 0xBF, 0x40, 0x9F, 0x60, 0x1B, 0xE4, 0x54, 0xAB]
    for _ in range(3):
        send_byte_array(byte_array)
        logger.debug("AC Split ON: Hexadecimal message sent.")

def turnOffAirconditionerSplit():
    byte_array = [0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xDF, 0x20, 0x6F, 0x90, 0x54, 0xAB]
    for _ in range(3):
        send_byte_array(byte_array)
        logger.debug("AC Split OFF: Hexadecimal message sent.")

# =======================
# HELPER FUNCTIONS
# =======================
_gpio_lock = threading.Lock()
_configured_pins = set()

def gpio_write(pin, level):
    """Drive an output pin, configuring it only the first time.

    Calling GPIO.setup(..., initial=HIGH) before every write briefly drove
    the pin HIGH even when switching it LOW.
    """
    with _gpio_lock:
        if pin in _configured_pins:
            GPIO.output(pin, level)
        else:
            GPIO.setup(pin, GPIO.OUT, initial=level)
            _configured_pins.add(pin)

def set_pin_state(pin, state):
    """Helper to set GPIO pin state and track it"""
    gpio_write(pin, GPIO.HIGH if state else GPIO.LOW)
    light_states[pin] = state

def parse_bool(value):
    return str(value).strip().lower() in ('on', 'true', '1', 'yes')

def parse_int(value, lo, hi, default):
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default

def apply_mode(modeType, on):
    """Switch to a lighting scene, or turn every light off."""
    global current_mode
    for pin in AllLights:
        set_pin_state(pin, False)
    if on:
        for pin in mode_arrays[modeType]:
            set_pin_state(pin, True)
        current_mode = modeType
    else:
        current_mode = None

# =======================
# WATER COOLER (RS485 + RELAYS)
# =======================
# Modbus RTU "write register" frames for fan levels 0 (off) to 19
COOLER_FAN_COMMANDS = [
    b'\x01\x10\x00\x00\x00\x01\x02\x00\x00\xA6\x50',
    b'\x01\x10\x00\x00\x00\x01\x02\x02\xBF\xE6\x80',
    b'\x01\x10\x00\x00\x00\x01\x02\x03\x8B\xE6\xC7',
    b'\x01\x10\x00\x00\x00\x01\x02\x04\x57\xE5\x6E',
    b'\x01\x10\x00\x00\x00\x01\x02\x05\x23\xE4\xD9',
    b'\x01\x10\x00\x00\x00\x01\x02\x05\xEF\xE4\x8C',
    b'\x01\x10\x00\x00\x00\x01\x02\x06\xBB\xE5\x83',
    b'\x01\x10\x00\x00\x00\x01\x02\x07\x87\xE4\x02',
    b'\x01\x10\x00\x00\x00\x01\x02\x08\x53\xE1\xAD',
    b'\x01\x10\x00\x00\x00\x01\x02\x09\x1F\xE1\xC8',
    b'\x01\x10\x00\x00\x00\x01\x02\x09\xEB\xE0\x4F',
    b'\x01\x10\x00\x00\x00\x01\x02\x0A\xB7\xE0\x86',
    b'\x01\x10\x00\x00\x00\x01\x02\x0B\x83\xE0\xC1',
    b'\x01\x10\x00\x00\x00\x01\x02\x0C\x4F\xE2\xA4',
    b'\x01\x10\x00\x00\x00\x01\x02\x0D\x1B\xE2\xCB',
    b'\x01\x10\x00\x00\x00\x01\x02\x0D\xE7\xE2\x8A',
    b'\x01\x10\x00\x00\x00\x01\x02\x0E\xB3\xE3\x85',
    b'\x01\x10\x00\x00\x00\x01\x02\x0F\x7F\xE2\x40',
    b'\x01\x10\x00\x00\x00\x01\x02\x10\x4B\xEB\xA7',
    b'\x01\x10\x00\x00\x00\x01\x02\x11\x17\xEA\x0E'
]
# The table goes to 19, but this cooler's top speed is level 5. Everything
# - the slider, the + button, the server check - follows this one number,
# so nothing above 5 can be sent from any page or old shortcut.
COOLER_MAX_LEVEL = 5

# Force USB-RS485 adapter port (CH340)
COOLER_SERIAL_PORT = '/dev/ttyUSB0'
COOLER_BAUD_RATE = 9600
_serial_lock = threading.Lock()

def send_cooler_fan_level(fanLevel):
    """Send the RS485 fan command. Returns (ok, message)."""
    if not 0 <= fanLevel <= COOLER_MAX_LEVEL:
        return False, f"Fan level must be 0-{COOLER_MAX_LEVEL}"
    selected_row = COOLER_FAN_COMMANDS[fanLevel]
    try:
        # One writer at a time - the worker and a manual request used to
        # open the port together and interleave their frames.
        with _serial_lock, serial.Serial(COOLER_SERIAL_PORT, COOLER_BAUD_RATE, timeout=1) as ser:
            # Send command 5 times with 200ms delay (for reliability)
            for i in range(5):
                bytes_written = ser.write(selected_row)
                logger.debug(f"Cooler command sent ({i+1}/5): {bytes_written} bytes")
                time.sleep(0.2)
        logger.info(f"Water cooler fan level set to: {fanLevel}")
        return True, f"Water cooler fan set to level {fanLevel}"
    except PermissionError:
        logger.error(f"Permission denied on {COOLER_SERIAL_PORT}. User not in dialout group?")
        return False, "Permission denied. Check dialout group membership"
    except serial.SerialException as e:
        logger.error(f"Serial port error: {e}")
        return False, f"Serial error: {e}"
    except Exception as e:
        logger.error(f"Unexpected error sending cooler command: {e}")
        return False, f"Unexpected error: {e}"


# =======================
# HOUSE SETTINGS (instance/settings.json)
# =======================
def setting(key, label, kind, default, lo=None, hi=None, step=1, unit='', hint=''):
    return {'key': key, 'label': label, 'kind': kind, 'type': kind.__name__, 'default': default,
            'min': lo, 'max': hi, 'step': step, 'unit': unit, 'hint': hint}

# Shown in this order on the settings panel: (section, icon, fields)
HOUSE_SETTINGS = [
    ("Motorcycle", "fa-motorcycle", [
        setting('motoOpenSeconds', 'Opening time', float, 14, 2, 120, 0.5, 's',
                'After the first press, wait this long, then press again to stop the door'),
        setting('motoHoldSeconds', 'Stay open', float, 12, 2, 300, 0.5, 's',
                'How long the door waits half open before it closes'),
    ]),
    ("Doors", "fa-door-open", [
        setting('parkingPressSeconds', 'Parking remote press', float, 1, 0.1, 3, 0.1, 's',
                'How long each press of the parking remote lasts'),
        setting('mainDoorPressSeconds', 'Main door press', float, 0.1, 0.05, 3, 0.05, 's',
                'How long the main door lock is released'),
        setting('doorConfirmSeconds', 'Second tap window', int, 3, 1, 10, 1, 's',
                'Without a fingerprint, the second tap must come within this time'),
    ]),
    ("Water cooler defaults", "fa-fan", [
        setting('coolerFanLevel', 'Fan speed', int, 3, 1, COOLER_MAX_LEVEL, 1, ''),
        setting('coolerLength', 'Run for', int, 30, 1, 24 * 60, 5, 'min'),
        setting('coolerWaterPump', 'Water pump', bool, False),
        setting('coolerFanBetween', 'Channel fan', bool, False),
        setting('coolerRepeat', 'Repeat', bool, False, hint='Rest, then run again'),
        setting('coolerInterval', 'Rest between runs', int, 30, 1, 24 * 60, 5, 'min'),
    ]),
    ("Split AC", "fa-snowflake", [
        setting('splitTemperature', 'Temperature', int, 23, 16, 30, 1, '°C'),
    ]),
    ("Lights", "fa-lightbulb", [
        setting('autoLightOnBoot', 'Automatic schedule after a restart', bool, False,
                hint='Turn the scene schedule on by itself when the Pi starts'),
    ]),
]

class HouseSettings:
    """Settings changed from the panel, kept across restarts in one JSON file."""

    def __init__(self, path, sections):
        self._path = path
        self._lock = threading.Lock()
        self.fields = {f['key']: f for _, _, fields in sections for f in fields}
        self.defaults = {k: f['default'] for k, f in self.fields.items()}
        self._values = dict(self.defaults)
        try:
            with open(path) as fh:
                self._values.update(self.clean(json.load(fh)))
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            logger.error(f"Could not read {path}, using defaults: {e}")

    def clean(self, src):
        """Keep known keys only, each turned into its type and kept in range."""
        out = {}
        if not isinstance(src, dict):
            return out
        for key, f in self.fields.items():
            if key not in src:
                continue
            value = src[key]
            if f['kind'] is bool:
                out[key] = value if isinstance(value, bool) else parse_bool(value)
                continue
            try:
                value = float(value)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(value):
                continue
            value = max(f['min'], min(f['max'], value))
            out[key] = int(round(value)) if f['kind'] is int else round(value, 2)
        return out

    def get(self, key):
        return self._values[key]

    def all(self):
        return dict(self._values)

    def update(self, src):
        changes = self.clean(src)
        with self._lock:
            self._values.update(changes)
            self._save()
        return changes

    def reset(self):
        with self._lock:
            self._values = dict(self.defaults)
            self._save()
        return self.all()

    def _save(self):
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp = self._path + '.tmp'
        with open(tmp, 'w') as fh:
            json.dump(self._values, fh, indent=2)
        os.replace(tmp, self._path)   # never leaves a half-written file


house = HouseSettings(os.path.join(base_dir, 'instance', 'settings.json'), HOUSE_SETTINGS)
ac_split_state['temperature'] = house.get('splitTemperature')

def cooler_defaults():
    return {
        'fanLevel': house.get('coolerFanLevel'), 'waterPump': house.get('coolerWaterPump'),
        'fanBetween': house.get('coolerFanBetween'), 'length': house.get('coolerLength'),
        'repeat': house.get('coolerRepeat'), 'interval': house.get('coolerInterval'),
    }


COOLER_TICK = 30   # seconds between command re-sends while cooling

class CoolerController:
    """Owns the water cooler, with exactly one worker thread at a time.

    Pressing "on" while a cycle is running now updates that cycle instead
    of starting another thread next to it. Settings changed while running
    (fan level, pump, timer) take effect immediately.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.settings = cooler_defaults()
        self.phase = 'off'           # off | cooling | resting
        self.phase_ends = None
        self.outputs = {'power': False, 'pump': False, 'fanBetween': False}
        self.last_error = None

    @property
    def running(self):
        return (self._thread is not None and self._thread.is_alive()
                and not self._stop.is_set())

    def status(self):
        running = self.running
        left = None
        if running and self.phase_ends:
            left = max(0, int(self.phase_ends - time.time()))
        return {
            'running': running,
            'phase': self.phase if running else 'off',
            'secondsLeft': left,
            'settings': dict(self.settings),
            'outputs': dict(self.outputs),
            'error': self.last_error,
        }

    @staticmethod
    def _bounded(changes):
        # Last line of defence for the top speed, whoever calls in
        if 'fanLevel' in changes:
            changes['fanLevel'] = max(0, min(COOLER_MAX_LEVEL, int(changes['fanLevel'])))
        return changes

    def use_defaults(self, defaults):
        """New defaults from the settings panel. A running cycle keeps its own."""
        with self._lock:
            if not self.running:
                self.settings.update(self._bounded(dict(defaults)))
        return self.status()

    def configure(self, **changes):
        changes = self._bounded(changes)
        with self._lock:
            self.settings.update(changes)
            if self.running:
                self._wake.set()
            elif 'fanBetween' in changes:
                # Fan between channels can also run on its own
                self._set_fan_between(changes['fanBetween'])
        return self.status()

    def start(self, **changes):
        changes = self._bounded(changes)
        with self._lock:
            self.settings.update(changes)
            if self.running:
                self._wake.set()
                return self.status()
            old = self._thread
        if old is not None:
            old.join(timeout=10)     # let a stopping worker finish switching off
        with self._lock:
            if not self.running:
                self.last_error = None
                self._stop = threading.Event()
                self._wake = threading.Event()
                self._thread = threading.Thread(
                    target=self._run, args=(self._stop, self._wake),
                    name='cooler', daemon=True)
                self._thread.start()
        return self.status()

    def stop(self):
        with self._lock:
            self._stop.set()
            self._wake.set()
            worker = self._thread
        if worker is not None and worker.is_alive():
            worker.join(timeout=10)
        else:
            self._switch_off()
        return self.status()

    def _set_fan_between(self, on):
        gpio_write(pinToType["Fan_Between_Channels_Switch"], GPIO.HIGH if on else GPIO.LOW)
        self.outputs['fanBetween'] = on

    def _switch_on(self, s):
        gpio_write(pinToType["Cooler_Pump"], GPIO.LOW if s['waterPump'] else GPIO.HIGH)
        self._set_fan_between(s['fanBetween'])
        gpio_write(pinToType["CoolerPower"], GPIO.LOW)
        self.outputs.update(power=True, pump=s['waterPump'])
        ok, msg = send_cooler_fan_level(s['fanLevel'])
        self.last_error = None if ok else msg

    def _switch_off(self):
        send_cooler_fan_level(0)
        time.sleep(1)
        gpio_write(pinToType["CoolerPower"], GPIO.HIGH)
        gpio_write(pinToType["Cooler_Pump"], GPIO.HIGH)
        self._set_fan_between(False)
        self.outputs.update(power=False, pump=False)

    def _run(self, stop, wake):
        logger.debug("Cooler worker started")
        try:
            while not stop.is_set():
                cycle_start = time.time()
                self.phase = 'cooling'
                while not stop.is_set():
                    wake.clear()
                    s = dict(self.settings)
                    self.phase_ends = cycle_start + s['length'] * 60
                    remaining = self.phase_ends - time.time()
                    if remaining <= 0:
                        break
                    self._switch_on(s)
                    wake.wait(min(COOLER_TICK, remaining))

                logger.debug('Cooler cycle complete, turning off')
                self._switch_off()
                if stop.is_set() or not self.settings['repeat']:
                    break

                rest_start = time.time()
                self.phase = 'resting'
                while not stop.is_set() and self.settings['repeat']:
                    wake.clear()
                    self.phase_ends = rest_start + self.settings['interval'] * 60
                    remaining = self.phase_ends - time.time()
                    if remaining <= 0:
                        break
                    wake.wait(remaining)
                if not self.settings['repeat']:
                    break
        except Exception:
            logger.exception('Cooler worker crashed')
        finally:
            if self.outputs['power']:
                self._switch_off()
            with self._lock:
                if self._thread is threading.current_thread():
                    self.phase = 'off'
                    self.phase_ends = None
            logger.debug("Cooler worker stopped")


cooler = CoolerController()


def cooler_settings_from(src):
    """Read cooler settings from a form or JSON body, keeping only what was sent."""
    out = {}
    if 'fanLevel' in src:
        out['fanLevel'] = parse_int(src['fanLevel'], 0, COOLER_MAX_LEVEL, 3)
    if 'waterPump' in src:
        out['waterPump'] = parse_bool(src['waterPump'])
    if 'fanBetween' in src:
        out['fanBetween'] = parse_bool(src['fanBetween'])
    if 'length' in src:
        out['length'] = parse_int(src['length'], 1, 24 * 60, 30)
    if 'repeat' in src:
        out['repeat'] = parse_bool(src['repeat'])
    if 'interval' in src:
        out['interval'] = parse_int(src['interval'], 1, 24 * 60, 30)
    return out

# =======================
# AUTO LIGHT MODE
# =======================
AUTO_LIGHT_SCHEDULE = [
    ("07:00", "BREAKFAST_MODE"),
    ("08:00", "NORMAL_DAY"),
    ("11:00", "COOKING_MODE"),
    ("13:00", "LUNCH_MODE"),
    ("14:00", "NORMAL_DAY"),
    ("15:00", "RELAX_MODE"),
    ("17:00", "NORMAL_NIGHT_MODE"),
    ("18:30", "COOKING_MODE"),
    ("20:00", "DINNER_MODE"),
    ("21:00", "RELAX_MODE"),
    ("22:30", None),            # all lights off
]

class AutoLightController:
    """Switches scenes on a daily schedule, with one thread at most."""

    def __init__(self):
        self._lock = threading.Lock()
        self._thread = None
        self._stop = threading.Event()

    @property
    def enabled(self):
        return (self._thread is not None and self._thread.is_alive()
                and not self._stop.is_set())

    def start(self):
        with self._lock:
            if self.enabled:
                return
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._run, args=(self._stop,),
                                            name='auto-light', daemon=True)
            self._thread.start()

    def stop(self):
        with self._lock:
            self._stop.set()

    def _run(self, stop):
        logger.debug('Auto Light Mode thread started')
        schedule = dict(AUTO_LIGHT_SCHEDULE)
        last_applied = None
        while not stop.is_set():
            now = datetime.now()
            slot = now.strftime("%H:%M")
            key = now.strftime("%Y-%m-%d ") + slot
            if slot in schedule and key != last_applied:
                mode = schedule[slot]
                # Called directly: the old HTTP call to /set_mode had no
                # login session and only ever reached the login page.
                apply_mode(mode, on=mode is not None)
                logger.info(f"Auto Light Mode applied {mode or 'all off'}")
                last_applied = key
            stop.wait(20)
        logger.debug('Auto Light Mode thread stopped')


auto_light = AutoLightController()

# =======================
# AUTHENTICATION ROUTES
# =======================
def remember_device(response, username):
    """Note on this browser which account it has a fingerprint key for."""
    if passkeys.available and passkeys.count(username) > 0:
        response.set_cookie(DEVICE_COOKIE, passkeys.device_cookie_value(username),
                            max_age=DEVICE_TTL, secure=True, httponly=True, samesite='Lax')
    return response

def login_page(error=None):
    # Start the fingerprint prompt by itself only when this browser is
    # known to hold a registered key - a prompt that ends in "no passkeys
    # found" is the worst thing to greet someone with. And not straight
    # after logging out, or the logout button would log you back in.
    auto = False
    if passkeys.available and not session.pop('pk_no_auto', False):
        known = passkeys.device_user(request.cookies.get(DEVICE_COOKIE))
        auto = bool(known and known in users_db and passkeys.count(known) > 0)
    return render_template('home_login.html', error=error,
                           pk_ready=passkeys.available, pk_rp_id=PASSKEY_RP_ID, pk_auto=auto)

def locked_message(seconds):
    return f"Too many failed attempts. Try again in {max(1, (seconds + 59) // 60)} minute(s)."

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        who = client_ip()
        wait = login_gate.locked_for(who)
        if wait:
            return login_page(locked_message(wait)), 429

        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        if username in users_db and bcrypt.check_password_hash(users_db[username], password):
            login_gate.reset(who)
            login_user(User(username), remember=remember)
            logger.info(f"User {username} logged in successfully")
            return remember_device(redirect('/'), username)
        else:
            login_gate.fail(who)
            logger.warning(f"Failed login attempt for user: {username} from {who}")
            return login_page('Invalid username or password')

    if current_user.is_authenticated:
        return redirect('/')
    return login_page()

@app.route("/logout")
@login_required
def logout():
    logger.info(f"User {current_user.id} logged out")
    logout_user()
    session['pk_no_auto'] = True
    return redirect('/login')

# =======================
# FINGERPRINT LOGIN (WebAuthn passkeys)
# =======================
def pk_reply(ok=True, status=200, **data):
    data['ok'] = ok
    resp = jsonify(data)
    resp.headers['Cache-Control'] = 'no-store'
    return resp, status

def pk_body():
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}

@app.route("/passkey/login/options", methods=['POST'])
def passkey_login_options():
    if not passkeys.available:
        return pk_reply(False, 404, error='Fingerprint login is not set up on this server.')
    wait = login_gate.locked_for(client_ip())
    if wait:
        return pk_reply(False, 429, error=locked_message(wait))
    known = passkeys.device_user(request.cookies.get(DEVICE_COOKIE))
    handle, options = passkeys.request_options(known if known in users_db else None)
    session['pk_ch'] = handle
    return pk_reply(options=options)

@app.route("/passkey/login/verify", methods=['POST'])
def passkey_login_verify():
    if not passkeys.available:
        return pk_reply(False, 404, error='Fingerprint login is not set up on this server.')
    who = client_ip()
    wait = login_gate.locked_for(who)
    if wait:
        return pk_reply(False, 429, error=locked_message(wait))
    try:
        username = passkeys.login_verify(session.pop('pk_ch', None), pk_body())
    except PasskeyError as e:
        login_gate.fail(who)
        logger.warning(f"Fingerprint login failed from {who}: {e}")
        return pk_reply(False, 401, error=str(e))
    if username not in users_db:
        login_gate.fail(who)
        return pk_reply(False, 401, error='The account for this device no longer exists.')
    login_gate.reset(who)
    login_user(User(username), remember=True)
    logger.info(f"User {username} logged in with fingerprint")
    resp, status = pk_reply(go='/')
    return remember_device(resp, username), status

@app.route("/passkey/register/options", methods=['POST'])
@login_required
def passkey_register_options():
    if not passkeys.available:
        return pk_reply(False, 404, error='Fingerprint login is not set up on this server.')
    handle, options = passkeys.create_options(current_user.id, compat=bool(pk_body().get('compat')))
    session['pk_ch'] = handle
    return pk_reply(options=options)

@app.route("/passkey/register/verify", methods=['POST'])
@login_required
def passkey_register_verify():
    if not passkeys.available:
        return pk_reply(False, 404, error='Fingerprint login is not set up on this server.')
    try:
        result = passkeys.register_verify(current_user.id, session.pop('pk_ch', None), pk_body(),
                                          request.headers.get('User-Agent', ''))
    except PasskeyError as e:
        return pk_reply(False, 400, error=str(e))
    logger.info(f"User {current_user.id} registered a fingerprint device")
    resp, status = pk_reply(**result)
    return remember_device(resp, current_user.id), status

@app.route("/passkey/devices", methods=['GET'])
@login_required
def passkey_devices():
    if not passkeys.available:
        return pk_reply(devices=[], ready=False)
    devices = [{'id': k['id'], 'label': k['label'], 'created': k['created_at'][:10],
                'lastUsed': (k['last_used_at'] or '')[:10], 'localOnly': k['discoverable'] == 0}
               for k in passkeys.list(current_user.id)]
    return pk_reply(devices=devices, ready=True)

@app.route("/passkey/remove", methods=['POST'])
@login_required
def passkey_remove():
    try:
        key_id = int(pk_body().get('id'))
    except (TypeError, ValueError):
        return pk_reply(False, 400, error='Unknown device.')
    if not passkeys.remove(current_user.id, key_id):
        return pk_reply(False, 404, error='That device was already removed.')
    resp, status = pk_reply(msg='Device removed.')
    # No keys left: the note on this browser has nothing to point at
    if passkeys.count(current_user.id) == 0 and \
            passkeys.device_user(request.cookies.get(DEVICE_COOKIE)) == current_user.id:
        resp.delete_cookie(DEVICE_COOKIE)
    return resp, status

# =======================
# WEB ROUTES
# =======================
@app.route("/")
@login_required
def index():
    light_groups = [
        (area, icon, [(pinToType[key], label) for key, label in lights])
        for area, icon, lights in LIGHT_GROUPS
    ]
    resp = app.make_response(render_template(
        'index.html', username=current_user.id,
        light_groups=light_groups, scenes=SCENES,
        cooler_max=COOLER_MAX_LEVEL, base_domain=BASE_DOMAIN,
        pk_ready=passkeys.available, pk_rp_id=PASSKEY_RP_ID,
        door_pk=door_needs_fingerprint(),
        settings_sections=HOUSE_SETTINGS, house=house.all()))
    # Sessions opened before a key was registered get the device note too,
    # so the next login can start the fingerprint prompt by itself
    if passkeys.available and \
            passkeys.device_user(request.cookies.get(DEVICE_COOKIE)) != current_user.id:
        remember_device(resp, current_user.id)
    return resp

# =======================
# INSTALLABLE APP (PWA)
# =======================
# Both public: the browser reads them before anyone has logged in, and
# neither says anything about the house.
@app.route('/manifest.webmanifest')
def web_manifest():
    icon = lambda name, size, purpose: {'src': f'/static/images/{name}', 'sizes': size,
                                        'type': 'image/png', 'purpose': purpose}
    resp = jsonify({
        'id': '/',
        'name': 'Parsa Home',
        'short_name': 'Parsa Home',
        'description': 'Lights, cooler and doors of the house',
        'start_url': '/?src=app',
        'scope': '/',
        'display': 'standalone',
        'orientation': 'portrait',
        'background_color': '#0b1020',
        'theme_color': '#0b1020',
        'icons': [icon('icon-192.png', '192x192', 'any'),
                  icon('icon-512.png', '512x512', 'any'),
                  icon('icon-maskable-512.png', '512x512', 'maskable')],
        # long-press on the app icon
        'shortcuts': [{'name': 'Lights', 'url': '/#lights'},
                      {'name': 'Climate', 'url': '/#climate'},
                      {'name': 'Doors', 'url': '/#more'}],
    })
    resp.mimetype = 'application/manifest+json'
    resp.headers['Cache-Control'] = 'public, max-age=3600'
    return resp

@app.route('/sw.js')
def service_worker():
    # Served from the root so it may look after the whole site; never
    # cached, so a new version reaches phones on their next visit
    resp = send_from_directory(os.path.join(app.root_path, 'static', 'js'), 'sw.js',
                               mimetype='application/javascript', max_age=0)
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

@app.route('/images/<path:filename>')
def serve_image(filename):
    IMAGE_DIR = os.path.join(app.root_path, 'images')
    return send_from_directory(IMAGE_DIR, filename)

# =======================
# STATUS API
# =======================
@app.route("/get_status", methods=['GET'])
@login_required
def get_all_status():
    """Return current status of all components"""
    c = cooler.status()
    return jsonify({
        'lights': light_states,
        'currentMode': current_mode,
        'autoLightMode': auto_light.enabled,
        'cooler': c,
        'acSplitState': ac_split_state,
        # kept for older clients
        'airConditionerAuto': c['running'],
        'airConditionerOn': c['outputs']['power'],
        'acAutoState': {
            'running': c['running'],
            'fanLevel': c['settings']['fanLevel'],
            'waterPump': c['settings']['waterPump'],
            'fanBetween': c['settings']['fanBetween'],
        },
        'fanBetweenChannels': c['outputs']['fanBetween'],
        'parking': parking.status(),
    })

# =======================
# LIGHT CONTROL ROUTES
# =======================
KNOWN_PINS = set(pinToType.values())

def _pin_from_request():
    try:
        pin = int(request.form['pin'])
    except (KeyError, ValueError):
        abort(400, 'pin must be a number')
    if pin not in KNOWN_PINS:
        abort(400, f'pin {pin} is not connected to anything')
    return pin

def _switch_pin(state):
    pin = _pin_from_request()
    if pin == pinToType["Fan_Between_Channels_Switch"]:
        cooler.configure(fanBetween=state)
    else:
        set_pin_state(pin, state)
    word = "ON" if state else "OFF"
    logger.debug(f"Pin {pin} turned {word} by {current_user.id}")
    return jsonify({"status": "success", "pin": pin, "state": word.lower()})

@app.route("/on", methods=['POST'])
@login_required
def turn_on():
    return _switch_pin(True)

@app.route("/off", methods=['POST'])
@login_required
def turn_off():
    return _switch_pin(False)

@app.route("/status", methods=['GET'])
@login_required
def get_status():
    """Get single pin status"""
    try:
        pin = int(request.args.get('pin'))
    except (TypeError, ValueError):
        abort(400, 'pin must be a number')
    state = "on" if light_states.get(pin) else "off"
    return f"Pin {pin} is {state}"

@app.route("/set_light_status", methods=['POST'])
@login_required
def setLightStatus():
    """Set all lights on or off"""
    global current_mode
    status = request.form.get('status', 'off')
    state = status.lower() == "on"
    for pin in AllLights:
        set_pin_state(pin, state)
    current_mode = None
    logger.debug(f"All lights turned {status.upper()} by {current_user.id}")
    return jsonify({"status": "success", "allLights": status})

# =======================
# MODE CONTROL ROUTES
# =======================
@app.route("/set_mode", methods=['POST'])
@login_required
def setMode():
    modeType = request.form.get('modeType', '')
    on = request.form.get('status', '').lower() == "on"

    if modeType == "AUTO_LIGHT_MODE":
        if on:
            auto_light.start()
        else:
            auto_light.stop()
        logger.debug(f"Auto Light Mode {'ON' if on else 'OFF'} by {current_user.id}")
    elif modeType in mode_arrays:
        apply_mode(modeType, on)
        logger.debug(f"Mode {modeType} {'activated' if on else 'deactivated'} by {current_user.id}")
    else:
        return jsonify({"status": "error", "message": f"Unknown mode {modeType}"}), 400

    return jsonify({"status": "success", "mode": modeType, "state": "on" if on else "off"})

# =======================
# AIR CONDITIONER ROUTES
# =======================
@app.route("/set_airconditionerSplit", methods=['POST'])
@login_required
def setAirconditionerSplit():
    logger.debug(f'AC Split command received from {current_user.id}')

    status = request.form.get('status', 'off')
    if status.lower() == "on":
        ac_split_state['running'] = True
        ac_split_state['temperature'] = parse_int(request.form.get('tempSet'), 16, 30, 23)
        turnOnAirconditionerSplit()
    else:
        ac_split_state['running'] = False
        turnOffAirconditionerSplit()

    return jsonify({"status": "success", "ac_split": status})

@app.route("/cooler", methods=['POST'])
@login_required
def cooler_control():
    """Water cooler: action = start | stop | update, plus any settings."""
    src = request.get_json(silent=True) or request.form
    action = (src.get('action') or 'update').lower()
    settings = cooler_settings_from(src)

    if action == 'start':
        state = cooler.start(**settings)
    elif action == 'stop':
        if settings:
            cooler.configure(**settings)
        state = cooler.stop()
    elif action == 'update':
        state = cooler.configure(**settings)
    else:
        return jsonify({"status": "error", "message": f"Unknown action {action}"}), 400

    logger.debug(f"Cooler {action} {settings} by {current_user.id}")
    return jsonify({"status": "success", "cooler": state})

@app.route("/set_airconditionerAuto", methods=['POST'])
@login_required
def setAirconditionerAuto():
    """Older form-based endpoint, mapped onto the single cooler worker."""
    f = request.form
    settings = cooler_settings_from({
        k: v for k, v in {
            'fanLevel': f.get('fanLevel'),
            'waterPump': f.get('waterPumpStatus'),
            'fanBetween': f.get('fanBtwChannelStatus'),
            'length': f.get('length'),
            'repeat': f.get('repeat'),
            'interval': f.get('everyTimeMinute'),
        }.items() if v is not None
    })
    status = f.get('status', 'off')
    if status.lower() == "on":
        cooler.start(**settings)
    else:
        cooler.stop()
    return jsonify({"status": "success", "ac_auto": status})

@app.route("/set_airconditioner", methods=['POST'])
@login_required
def setAirconditioner():
    """Send RS485 command to water cooler controller via USB-RS485"""
    try:
        fanLevel = int(request.form['fanLevel'])
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid fanLevel parameter: {e}")
        return jsonify({"status": "error", "message": "Invalid fan level"}), 400

    ok, message = send_cooler_fan_level(fanLevel)
    if not ok:
        return jsonify({"status": "error", "message": message}), 400 if 'must be' in message else 500
    return jsonify({"status": "success", "fanLevel": fanLevel, "message": message})

# =======================
# DOOR CONTROL ROUTES
# =======================
def pulse(pin, seconds):
    gpio_write(pin, GPIO.LOW)
    time.sleep(seconds)
    gpio_write(pin, GPIO.HIGH)

class ParkingDoor:
    """The parking remote, and the motorcycle trip that uses it.

    The remote has one button: each press starts, stops or reverses the
    door. A motorcycle needs only part of the opening, so its trip is
    press (opening), wait, press (door stops part way), wait, press
    (closing). Tapping the motorcycle button again meanwhile does
    nothing. The car button cancels the trip and presses once, as it
    always did.
    """
    GAP = 0.5   # rest between two presses, so they never merge into one long one

    def __init__(self, pin):
        self.pin = pin
        self._press_lock = threading.Lock()
        self._lock = threading.Lock()
        self._thread = None
        self._cancel = threading.Event()
        self._last_release = 0.0
        self.step = None          # opening | holding | closing
        self.step_ends = None

    def press(self):
        with self._press_lock:
            wait = self._last_release + self.GAP - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            try:
                pulse(self.pin, house.get('parkingPressSeconds'))
            finally:
                self._last_release = time.monotonic()

    @property
    def moto_running(self):
        t = self._thread
        return t is not None and t.is_alive()

    def status(self):
        running = self.moto_running
        ends = self.step_ends
        return {
            'motoRunning': running,
            'motoStep': self.step if running else None,
            'secondsLeft': max(0, round(ends - time.time(), 1)) if running and ends else None,
        }

    def moto(self, who):
        """Start the motorcycle trip. False if one is already running."""
        with self._lock:
            if self.moto_running:
                return False
            self._cancel = threading.Event()
            self.step, self.step_ends = 'opening', None
            self._thread = threading.Thread(target=self._moto_run, args=(self._cancel, who),
                                            name='parking-moto', daemon=True)
            self._thread.start()
        return True

    def car(self):
        """One press of the remote. Returns True if it cancelled a motorcycle trip."""
        with self._lock:
            worker = self._thread if self.moto_running else None
            self._cancel.set()
            if worker is not None:
                worker.join(timeout=10)   # a press in progress finishes first
            self.press()
        return worker is not None

    def _moto_run(self, cancel, who):
        plan = (('opening', 'motoOpenSeconds'), ('holding', 'motoHoldSeconds'), ('closing', None))
        logger.info(f"Motorcycle trip started by {who}")
        try:
            for step, wait_key in plan:
                if cancel.is_set():
                    break
                # the wait counts from the start of the press, as set in the panel
                ends = time.time() + house.get(wait_key) if wait_key else None
                self.step, self.step_ends = step, ends
                self.press()
                if ends and cancel.wait(max(0, ends - time.time())):
                    break
            if cancel.is_set():
                logger.info("Motorcycle trip cancelled by the car button")
            else:
                logger.info("Motorcycle trip finished")
        except Exception:
            logger.exception('Motorcycle trip crashed')
        finally:
            self.step, self.step_ends = None, None


parking = ParkingDoor(pinToType["Parking_Remote"])

DOOR_ACTIONS = ('door:main', 'door:parking', 'door:moto')

def on_passkey_host():
    host = request.host.split(':')[0].lower()
    return host == PASSKEY_RP_ID or host.endswith('.' + PASSKEY_RP_ID)

def door_needs_fingerprint():
    """Doors open only with a fingerprint once the account has one set up.

    Except on an address where browsers cannot do fingerprints at all (the
    LAN IP over plain http): there the page keeps its tap-twice button, so
    the doors still work from home when the internet is down.
    """
    return passkeys.available and on_passkey_host() and passkeys.count(current_user.id) > 0

@app.route("/passkey/confirm/options", methods=['POST'])
@login_required
def passkey_confirm_options():
    action = str(pk_body().get('action', ''))
    if action not in DOOR_ACTIONS:
        return pk_reply(False, 400, error='Unknown action.')
    if not passkeys.available:
        return pk_reply(False, 404, error='Fingerprint login is not set up on this server.')
    try:
        handle, options = passkeys.confirm_options(current_user.id, action)
    except PasskeyError as e:
        return pk_reply(False, 400, error=str(e))
    session['pk_confirm'] = handle
    return pk_reply(options=options)

def door_refused(action, name):
    """None when the door may move, otherwise the reply that refuses it."""
    if not door_needs_fingerprint():
        return None
    who = client_ip()
    wait = login_gate.locked_for(who)
    if wait:
        return pk_reply(False, 429, error=locked_message(wait))
    assertion = pk_body().get('assertion')
    if not isinstance(assertion, dict):
        # The page asks for the fingerprint and sends it with the retry
        return pk_reply(False, 428, needFingerprint=True, error='Confirm with your fingerprint.')
    try:
        passkeys.confirm_verify(current_user.id, session.pop('pk_confirm', None), assertion, action)
    except PasskeyError as e:
        login_gate.fail(who)
        logger.warning(f"{name} not opened for {current_user.id}: {e}")
        return pk_reply(False, 403, error=str(e))
    login_gate.reset(who)
    return None

def moto_busy_reply():
    return pk_reply(False, 409, busy=True, parking=parking.status(),
                    error='The motorcycle trip is still running.')

@app.route("/ParkingDoorToggle", methods=['POST'])
@login_required
def toggleParkingDoor():
    refused = door_refused('door:parking', "Parking door")
    if refused:
        return refused
    cancelled = parking.car()
    logger.info(f"Parking door pressed by {current_user.id}" + (" (motorcycle trip cancelled)" if cancelled else ""))
    return jsonify({"status": "success", "ok": True, "door": "parking",
                    "cancelledMoto": cancelled, "parking": parking.status()})

@app.route("/ParkingMotoToggle", methods=['POST'])
@login_required
def toggleParkingMoto():
    # Checked before the fingerprint too: a tap during the trip does nothing
    if parking.moto_running:
        return moto_busy_reply()
    refused = door_refused('door:moto', "Parking door (motorcycle)")
    if refused:
        return refused
    if not parking.moto(current_user.id):
        return moto_busy_reply()
    return jsonify({"status": "success", "ok": True, "door": "moto", "parking": parking.status()})

@app.route("/MainDoorToggle", methods=['POST'])
@login_required
def toggleMainDoor():
    refused = door_refused('door:main', "Main door")
    if refused:
        return refused
    pulse(pinToType["Main_Door"], house.get('mainDoorPressSeconds'))
    logger.info(f"Main door opened by {current_user.id}")
    return jsonify({"status": "success", "ok": True, "door": "main"})

# =======================
# SETTINGS PANEL
# =======================
def apply_house_settings():
    cooler.use_defaults(cooler_defaults())
    if not ac_split_state['running']:
        ac_split_state['temperature'] = house.get('splitTemperature')

@app.route("/house_settings", methods=['GET', 'POST'])
@login_required
def house_settings():
    if request.method == 'POST':
        body = request.get_json(silent=True) or {}
        if body.get('reset'):
            house.reset()
            logger.info(f"Settings reset to defaults by {current_user.id}")
        else:
            changes = house.update(body.get('settings'))
            logger.info(f"Settings changed by {current_user.id}: {changes}")
        apply_house_settings()
    return jsonify({"status": "success", "settings": house.all(), "defaults": house.defaults})

# =======================
# CHILD SERVERS (upload, firmware)
# =======================
def start_child_server(script, log_name):
    """Start one of the side servers with its output going to logs/.

    stdout/stderr used to be PIPEs that nobody read. Once the pipe buffer
    filled up with request logs, the child blocked and stopped answering.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    log = open(os.path.join(LOG_DIR, log_name), 'ab')
    try:
        return subprocess.Popen(
            ['python3', script], cwd=base_dir,
            stdout=log, stderr=subprocess.STDOUT,
            preexec_fn=os.setsid)
    finally:
        log.close()      # the child keeps its own copy

def stop_child_server(proc):
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait(timeout=5)

# =======================
# UPLOAD SERVER CONTROL
# =======================
@app.route("/get_upload_server_status", methods=['GET'])
@login_required
def get_upload_server_status():
    """Check if upload server is running"""
    global upload_server_process, upload_server_enabled

    if upload_server_process is not None:
        if upload_server_process.poll() is None:
            upload_server_enabled = True
        else:
            upload_server_enabled = False
            upload_server_process = None

    return jsonify({
        "running": upload_server_enabled,
        "port": 8000 if upload_server_enabled else None
    })

@app.route("/toggle_upload_server", methods=['POST'])
@login_required
def toggle_upload_server():
    """Start or stop the upload server"""
    global upload_server_process, upload_server_enabled

    action = request.form.get('action', 'toggle')

    try:
        if action == 'on' or (action == 'toggle' and not upload_server_enabled):
            if upload_server_process is None or upload_server_process.poll() is not None:
                upload_server_path = os.path.join(base_dir, 'uploadServer.py')

                if not os.path.exists(upload_server_path):
                    logger.error(f"Upload server file not found: {upload_server_path}")
                    return jsonify({
                        "success": False,
                        "message": "Upload server file not found",
                        "running": False
                    })

                upload_server_process = start_child_server(upload_server_path, 'uploadServer.log')
                logger.info(f"Upload server started by {current_user.id} on port 8000")

            upload_server_enabled = True
            return jsonify({
                "success": True,
                "message": "Upload server started on port 8000",
                "running": True,
                "port": 8000
            })

        else:
            if upload_server_process is not None and upload_server_process.poll() is None:
                stop_child_server(upload_server_process)
                upload_server_process = None
                upload_server_enabled = False

                logger.info(f"Upload server stopped by {current_user.id}")

                return jsonify({
                    "success": True,
                    "message": "Upload server stopped",
                    "running": False
                })
            else:
                upload_server_process = None
                upload_server_enabled = False
                return jsonify({
                    "success": False,
                    "message": "Upload server is not running",
                    "running": False
                })

    except Exception as e:
        logger.error(f"Error toggling upload server: {e}")
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}",
            "running": upload_server_enabled
        })

# =======================
# FIRMWARE SERVER CONTROL
# =======================
firmwareserverprocess = None
firmwareserverenabled = False

@app.route('/get_firmware_server_status', methods=['GET'])
@login_required
def get_firmware_server_status():
    global firmwareserverprocess, firmwareserverenabled
    if firmwareserverprocess is not None:
        if firmwareserverprocess.poll() is None:
            firmwareserverenabled = True
        else:
            firmwareserverenabled = False
            firmwareserverprocess = None
    return jsonify(running=firmwareserverenabled, port=5001 if firmwareserverenabled else None)

@app.route('/toggle_firmware_server', methods=['POST'])
@login_required
def toggle_firmware_server():
    global firmwareserverprocess, firmwareserverenabled
    action = request.form.get('action', 'toggle')
    alive = firmwareserverprocess is not None and firmwareserverprocess.poll() is None
    if action == 'toggle':
        action = 'off' if alive else 'on'
    try:
        if action == 'on':
            if not alive:
                path = os.path.join(base_dir, 'firmware_server-3.py')
                if not os.path.exists(path):
                    return jsonify(success=False, message='Firmware server file not found', running=False)
                firmwareserverprocess = start_child_server(path, 'firmwareServer.log')
            firmwareserverenabled = True
            return jsonify(success=True, message='Firmware server started on port 5001', running=True, port=5001)
        elif alive:
            stop_child_server(firmwareserverprocess)
            firmwareserverprocess = None
            firmwareserverenabled = False
            return jsonify(success=True, message='Firmware server stopped', running=False)
        else:
            firmwareserverprocess = None
            firmwareserverenabled = False
            return jsonify(success=False, message='Firmware server is not running', running=False)
    except Exception as e:
        return jsonify(success=False, message=str(e), running=firmwareserverenabled)

# =======================
# VIDEO STREAMING
# =======================
rtsp_streams = [
    "rtsp://admin:Tn251316654871..@192.4.10.40:554/cam/realmonitor?channel=1&subtype=0",
    "rtsp://admin:Tn251316654871..@192.4.10.40:554/cam/realmonitor?channel=2&subtype=0",
    "rtsp://admin:Tn251316654871..@192.4.10.40:554/cam/realmonitor?channel=3&subtype=0",
    "rtsp://admin:Tn251316654871..@192.4.10.40:554/cam/realmonitor?channel=4&subtype=0",
    "rtsp://admin:Tn251316654871..@192.4.10.40:554/cam/realmonitor?channel=5&subtype=0",
    "rtsp://admin:Tn251316654871..@192.4.10.40:554/cam/realmonitor?channel=6&subtype=0",
    "rtsp://admin:Md6055608..@192.4.10.3:554/cam/realmonitor?channel=1&subtype=0",
    "rtsp://admin:Md6055608..@192.4.10.3:554/cam/realmonitor?channel=2&subtype=0",
    "rtsp://admin:Md6055608..@192.4.10.3:554/cam/realmonitor?channel=3&subtype=0",
    "rtsp://admin:Md6055608..@192.4.10.3:554/cam/realmonitor?channel=4&subtype=0",
    "rtsp://admin:Md6055608..@192.4.10.3:554/cam/realmonitor?channel=9&subtype=0",
    "rtsp://admin:Md6055608..@192.4.10.3:554/cam/realmonitor?channel=10&subtype=0"
]

def generate_frames(rtsp_stream):
    cap = cv2.VideoCapture(rtsp_stream)
    try:
        while True:
            success, frame = cap.read()
            if not success:
                break
            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
    finally:
        # Runs when the viewer closes the page too; without it every
        # closed stream left an RTSP connection open on the camera.
        cap.release()

@app.route('/video_feed/<int:stream_id>')
@login_required
def video_feed(stream_id):
    if not 0 <= stream_id < len(rtsp_streams):
        abort(404)
    return Response(generate_frames(rtsp_streams[stream_id]),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# =======================
# DATE AND WEATHER API
# =======================
SHAMSI_MONTHS = {
    1: 'فروردین', 2: 'اردیبهشت', 3: 'خرداد', 4: 'تیر',
    5: 'مرداد', 6: 'شهریور', 7: 'مهر', 8: 'آبان',
    9: 'آذر', 10: 'دی', 11: 'بهمن', 12: 'اسفند'
}
# jdatetime counts the week from Saturday (0) to Friday (6)
SHAMSI_WEEKDAYS = {
    0: 'شنبه', 1: 'یکشنبه', 2: 'دوشنبه', 3: 'سه‌شنبه',
    4: 'چهارشنبه', 5: 'پنج‌شنبه', 6: 'جمعه'
}

@app.route("/get_date_weather", methods=['GET'])
@login_required
def get_date_weather():
    """Return current date and weather information"""
    now = datetime.now()

    gregorian_date = now.strftime("%A, %B %d, %Y")

    j_date = jdatetime.datetime.now()
    shamsi_date = f"{SHAMSI_WEEKDAYS[j_date.weekday()]}، {j_date.day} {SHAMSI_MONTHS[j_date.month]} {j_date.year}"

    hour = now.hour
    if 5 <= hour < 12:
        time_of_day = "morning"
    elif 12 <= hour < 17:
        time_of_day = "noon"
    elif 17 <= hour < 20:
        time_of_day = "afternoon"
    else:
        time_of_day = "night"

    return jsonify({
        "gregorian": gregorian_date,
        "shamsi": shamsi_date,
        "time": now.strftime("%H:%M"),
        "timeOfDay": time_of_day,
        "weather": get_live_weather()
    })

WEATHER_TTL = 600        # seconds; every open page used to hit the API each minute
_weather_cache = {'at': 0, 'data': None}
_weather_lock = threading.Lock()

WEATHER_UNAVAILABLE = {
    "available": False, "temperature": None, "feels_like": None, "humidity": None,
    "wind_speed": None, "description": "Weather unavailable", "icon": "🌤️",
    "temp_min": None, "temp_max": None, "pressure": None, "visibility": None, "clouds": None
}

def get_live_weather():
    """Fetch live weather data from OpenWeatherMap API, cached for a few minutes"""
    with _weather_lock:
        if _weather_cache['data'] and time.time() - _weather_cache['at'] < WEATHER_TTL:
            return _weather_cache['data']

    API_KEY = "c7c93bfab61f0895a894456c66314a88"
    LAT = 35.6892
    LON = 51.3890

    url = f"https://api.openweathermap.org/data/2.5/weather?lat={LAT}&lon={LON}&appid={API_KEY}&units=metric"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        weather_icons = {
            "Clear": "☀️", "Clouds": "☁️", "Rain": "🌧️", "Drizzle": "🌦️",
            "Thunderstorm": "⛈️", "Snow": "❄️", "Mist": "🌫️", "Fog": "🌫️",
            "Haze": "🌫️", "Smoke": "🌫️", "Dust": "🌪️", "Sand": "🌪️",
            "Ash": "🌋", "Squall": "💨", "Tornado": "🌪️"
        }

        main_weather = data['weather'][0]['main']

        weather_info = {
            "available": True,
            "temperature": round(data['main']['temp']),
            "feels_like": round(data['main']['feels_like']),
            "humidity": data['main']['humidity'],
            "wind_speed": round(data['wind']['speed'] * 3.6),
            "description": data['weather'][0]['description'].title(),
            "icon": weather_icons.get(main_weather, "🌤️"),
            "temp_min": round(data['main']['temp_min']),
            "temp_max": round(data['main']['temp_max']),
            "pressure": data['main']['pressure'],
            "visibility": round(data.get('visibility', 0) / 1000, 1),
            "clouds": data['clouds']['all']
        }
        with _weather_lock:
            _weather_cache.update(at=time.time(), data=weather_info)
        logger.info(f"Weather data fetched successfully: {weather_info['temperature']}°C")
        return weather_info

    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching weather data: {e}")
    except (KeyError, IndexError, ValueError) as e:
        logger.error(f"Error parsing weather data: {e}")
    # Show "unavailable" rather than made-up numbers that look real
    return WEATHER_UNAVAILABLE

# =======================
# MAIN
# =======================
if __name__ == "__main__":
    logger.info("Initializing system - turning off all lights")
    for pin in AllLights:
        set_pin_state(pin, False)
    # Put the cooler relays in a known OFF state instead of whatever the
    # pins float to at boot
    gpio_write(pinToType["CoolerPower"], GPIO.HIGH)
    gpio_write(pinToType["Cooler_Pump"], GPIO.HIGH)
    gpio_write(pinToType["Fan_Between_Channels_Switch"], GPIO.LOW)

    if house.get('autoLightOnBoot'):
        logger.info("Automatic light schedule on, as set in the settings")
        auto_light.start()

    logger.info("Starting Flask server on port 5000")
    app.run(host='0.0.0.0', debug=False, port=5000, threaded=True)
