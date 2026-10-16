from flask import Flask, render_template, request, send_from_directory, Response, jsonify, redirect, abort
import RPi.GPIO as GPIO
from datetime import datetime
import logging
import sys
import threading
import requests
import os
import time
import serial
import cv2
import jdatetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import subprocess
import signal

from local_secrets import load_secret

# =======================
# CONFIGURATION
# =======================
base_dir = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(base_dir, 'logs')

app = Flask(__name__)

# Security configuration - a random key per install, see local_secrets.py
app.config['SECRET_KEY'] = load_secret('smarthome')
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Domain the upload and firmware servers are published under (install.sh sets it)
BASE_DOMAIN = os.environ.get('SMARTHOME_DOMAIN', 'turingco.ir')

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
COOLER_MAX_LEVEL = len(COOLER_FAN_COMMANDS) - 1

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
        self.settings = {
            'fanLevel': 3, 'waterPump': False, 'fanBetween': False,
            'length': 30, 'repeat': False, 'interval': 30,
        }
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

    def configure(self, **changes):
        with self._lock:
            self.settings.update(changes)
            if self.running:
                self._wake.set()
            elif 'fanBetween' in changes:
                # Fan between channels can also run on its own
                self._set_fan_between(changes['fanBetween'])
        return self.status()

    def start(self, **changes):
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
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        if username in users_db and bcrypt.check_password_hash(users_db[username], password):
            user = User(username)
            login_user(user, remember=remember)
            logger.info(f"User {username} logged in successfully")
            return redirect('/')
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            return render_template('home_login.html', error='Invalid username or password')

    return render_template('home_login.html')

@app.route("/logout")
@login_required
def logout():
    logger.info(f"User {current_user.id} logged out")
    logout_user()
    return redirect('/login')

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
    return render_template('index.html', username=current_user.id,
                           light_groups=light_groups, scenes=SCENES,
                           cooler_max=COOLER_MAX_LEVEL, base_domain=BASE_DOMAIN)

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

@app.route("/ParkingDoorToggle", methods=['POST'])
@login_required
def toggleParkingDoor():
    pulse(pinToType["Parking_Remote"], 1)
    logger.debug(f"Parking door toggled by {current_user.id}")
    return jsonify({"status": "success", "door": "parking"})

@app.route("/MainDoorToggle", methods=['POST'])
@login_required
def toggleMainDoor():
    pulse(pinToType["Main_Door"], 0.1)
    logger.debug(f"Main door toggled by {current_user.id}")
    return jsonify({"status": "success", "door": "main"})

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

    logger.info("Starting Flask server on port 5000")
    app.run(host='0.0.0.0', debug=False, port=5000, threaded=True)
