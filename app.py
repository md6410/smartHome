from flask import Flask, render_template, request, send_from_directory, Response, jsonify, redirect, url_for
import RPi.GPIO as GPIO
from datetime import datetime, timedelta
from time import sleep
import logging
import sys
import threading
import requests
import os
import time
import serial
import serial.tools.list_ports
import cv2
import jdatetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import subprocess
import signal

# =======================
# CONFIGURATION
# =======================
base_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

# Security configuration
app.config['SECRET_KEY'] = 'e31e40a3927daed0780af88f7ad96abcd08e53d35f2b7846'
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
auto_Light_mode_enabled = False
airConditioner_mode_enabled = False
isAutoAirconditionerOn = False
current_airconditioner_thread = None
fan_between_channels_state = False

# Upload server control
upload_server_process = None
upload_server_enabled = False

# AC state tracking
ac_auto_state = {
    'running': False,
    'fanLevel': 3,
    'waterPump': False,
    'fanBetween': False
}

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
def set_pin_state(pin, state):
    """Helper to set GPIO pin state and track it"""
    GPIO.setup(pin, GPIO.OUT, initial=GPIO.HIGH)
    GPIO.output(pin, GPIO.HIGH if state else GPIO.LOW)
    light_states[pin] = state

# =======================
# AUTHENTICATION ROUTES
# =======================
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember') == 'on'
        
        if username in users_db and bcrypt.check_password_hash(users_db[username], password):
            user = User(username)
            login_user(user, remember=remember)
            logger.info(f"User {username} logged in successfully")
            return redirect('/')
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

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
    gpio_pins = range(28)
    return render_template('index.html', gpio_pins=gpio_pins, username=current_user.id)

@app.route("/cctv.html")
@login_required
def cctv():
    return render_template("cctv.html")

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
    return jsonify({
        'lights': light_states,
        'currentMode': current_mode,
        'autoLightMode': auto_Light_mode_enabled,
        'airConditionerAuto': airConditioner_mode_enabled,
        'airConditionerOn': isAutoAirconditionerOn,
        'acAutoState': ac_auto_state,
        'acSplitState': ac_split_state,
        'fanBetweenChannels': fan_between_channels_state
    })

# =======================
# LIGHT CONTROL ROUTES
# =======================
@app.route("/on", methods=['POST'])
@login_required
def turn_on():
    global fan_between_channels_state
    pin = int(request.form['pin'])
    set_pin_state(pin, True)
    
    if pin == 4:
        fan_between_channels_state = True
    
    logger.debug(f"Pin {pin} turned ON by {current_user.id}")
    return jsonify({"status": "success", "pin": pin, "state": "on"})

@app.route("/off", methods=['POST'])
@login_required
def turn_off():
    global fan_between_channels_state
    pin = int(request.form['pin'])
    set_pin_state(pin, False)
    
    if pin == 4:
        fan_between_channels_state = False
    
    logger.debug(f"Pin {pin} turned OFF by {current_user.id}")
    return jsonify({"status": "success", "pin": pin, "state": "off"})

@app.route("/status", methods=['GET'])
@login_required
def get_status():
    """Get single pin status"""
    pin = int(request.args.get('pin'))
    state = "on" if GPIO.input(pin) else "off"
    return f"Pin {pin} is {state}"

@app.route("/set_light_status", methods=['POST'])
@login_required
def setLightStatus():
    """Set all lights on or off"""
    status = request.form['status']
    state = status.lower() == "on"
    for pin in AllLights:
        set_pin_state(pin, state)
    logger.debug(f"All lights turned {status.upper()} by {current_user.id}")
    return jsonify({"status": "success", "allLights": status})

# =======================
# MODE CONTROL ROUTES
# =======================
@app.route("/set_mode", methods=['POST'])
@login_required
def setMode():
    global auto_Light_mode_enabled, current_mode

    modeType = request.form['modeType']
    status = request.form['status']

    if modeType == "AUTO_LIGHT_MODE":
        if status.lower() == "on":
            auto_Light_mode_enabled = True
            current_mode = "AUTO_LIGHT_MODE"
            logger.debug(f'Auto Light Mode ON by {current_user.id}')
            auto_Light_mode_thread = threading.Thread(target=autoLightMode)
            auto_Light_mode_thread.daemon = True
            auto_Light_mode_thread.start()
        else:
            auto_Light_mode_enabled = False
            current_mode = None
            logger.debug(f'Auto Light Mode OFF by {current_user.id}')
    else:
        selectedTypeArray = mode_arrays.get(modeType, [])
        if status.lower() == "on":
            current_mode = modeType
            for pin in AllLights:
                set_pin_state(pin, False)
            for pin in selectedTypeArray:
                set_pin_state(pin, True)
            logger.debug(f"Mode {modeType} activated by {current_user.id}")
        else:
            current_mode = None
            for pin in AllLights:
                set_pin_state(pin, False)
            logger.debug(f"Mode {modeType} deactivated by {current_user.id}")

    return jsonify({"status": "success", "mode": modeType, "state": status})

# =======================
# AIR CONDITIONER ROUTES
# =======================
@app.route("/set_airconditionerSplit", methods=['POST'])
@login_required
def setAirconditionerSplit():
    global ac_split_state
    
    logger.debug(f'AC Split command received from {current_user.id}')

    status = request.form['status']
    tempSet = request.form.get('tempSet', 23)
    length = request.form['length']
    everyTimeMinute = request.form['everyTimeMinute']
    repeat = request.form['repeat']

    if status.lower() == "on":
        ac_split_state['running'] = True
        ac_split_state['temperature'] = int(tempSet)
        turnOnAirconditionerSplit()
    else:
        ac_split_state['running'] = False
        turnOffAirconditionerSplit()

    return jsonify({"status": "success", "ac_split": status})

@app.route("/set_airconditionerAuto", methods=['POST'])
@login_required
def setAirconditionerAuto():
    global airConditioner_mode_enabled, current_airconditioner_thread, ac_auto_state

    logger.debug(f'AC Auto command received from {current_user.id}')

    status = request.form['status']
    fanLevel = int(request.form['fanLevel'])
    length = request.form['length']
    everyTimeMinute = request.form['everyTimeMinute']
    repeat = request.form['repeat']
    waterPumpStatus = request.form['waterPumpStatus']
    betweenChannelPump = request.form['fanBtwChannelStatus']

    if status.lower() == "on":
        airConditioner_mode_enabled = True
        ac_auto_state['running'] = True
        ac_auto_state['fanLevel'] = fanLevel
        ac_auto_state['waterPump'] = waterPumpStatus.lower() == 'on'
        ac_auto_state['fanBetween'] = betweenChannelPump.lower() == 'on'
        
        logger.debug('AC Auto ON')
        
        if current_airconditioner_thread and current_airconditioner_thread.is_alive():
            airConditioner_mode_enabled = False
            current_airconditioner_thread.join(timeout=2)
            airConditioner_mode_enabled = True

        current_airconditioner_thread = threading.Thread(
            target=airconditionerMode,
            args=(fanLevel, length, everyTimeMinute, repeat, waterPumpStatus, betweenChannelPump)
        )
        current_airconditioner_thread.daemon = True
        current_airconditioner_thread.start()
    else:
        airConditioner_mode_enabled = False
        ac_auto_state['running'] = False
        logger.debug('AC Auto OFF')

    return jsonify({"status": "success", "ac_auto": status})

@app.route("/set_airconditioner", methods=['POST'])
@login_required
def setAirconditioner():
    """Send serial command to cooler controller"""
    fanLevel = int(request.form['fanLevel'])

    hex_array = [
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

    if 0 <= fanLevel < len(hex_array):
        selected_row = hex_array[fanLevel]
    else:
        selected_row = b'\x00' * 11

    ports = serial.tools.list_ports.comports()

    if len(ports) == 0:
        logger.warning("No serial ports found.")
        return jsonify({"status": "error", "message": "No serial ports found"})

    try:
        chosen_port = ports[0][0]
        baud_rate = 9600

        with serial.Serial(chosen_port, baud_rate, timeout=1) as ser:
            logger.debug(f"Serial port {chosen_port} opened at {baud_rate} baud.")
            for _ in range(5):
                ser.write(selected_row)
                time.sleep(0.2)
            logger.debug("Fan level command sent via serial")

        return jsonify({"status": "success", "fanLevel": fanLevel})

    except serial.SerialException as e:
        logger.error(f"Serial port error: {e}")
        return jsonify({"status": "error", "message": str(e)})

# =======================
# DOOR CONTROL ROUTES
# =======================
@app.route("/ParkingDoorToggle", methods=['POST'])
@login_required
def toggleParkingDoor():
    pin = pinToType["Parking_Remote"]
    GPIO.setup(pin, GPIO.OUT, initial=GPIO.HIGH)
    GPIO.output(pin, GPIO.LOW)
    sleep(1)
    GPIO.output(pin, GPIO.HIGH)
    logger.debug(f"Parking door toggled by {current_user.id}")
    return jsonify({"status": "success", "door": "parking"})

@app.route("/MainDoorToggle", methods=['POST'])
@login_required
def toggleMainDoor():
    pin = pinToType["Main_Door"]
    GPIO.setup(pin, GPIO.OUT, initial=GPIO.HIGH)
    GPIO.output(pin, GPIO.LOW)
    sleep(0.1)
    GPIO.output(pin, GPIO.HIGH)
    logger.debug(f"Main door toggled by {current_user.id}")
    return jsonify({"status": "success", "door": "main"})

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
                
                upload_server_process = subprocess.Popen(
                    ['python3', upload_server_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid
                )
                
                upload_server_enabled = True
                logger.info(f"Upload server started by {current_user.id} on port 8000")
                
                return jsonify({
                    "success": True,
                    "message": "Upload server started on port 8000",
                    "running": True,
                    "port": 8000
                })
        
        else:
            if upload_server_process is not None and upload_server_process.poll() is None:
                os.killpg(os.getpgid(upload_server_process.pid), signal.SIGTERM)
                upload_server_process.wait(timeout=5)
                upload_server_process = None
                upload_server_enabled = False
                
                logger.info(f"Upload server stopped by {current_user.id}")
                
                return jsonify({
                    "success": True,
                    "message": "Upload server stopped",
                    "running": False
                })
            else:
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
# BACKGROUND THREADS
# =======================
def autoLightMode():
    """Automatic lighting mode based on time of day"""
    global auto_Light_mode_enabled
    logger.debug('Auto Light Mode thread started')

    while auto_Light_mode_enabled:
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")

        time_modes = {
            ("07:00:00", "07:01:00"): "BREAKFAST_MODE",
            ("08:00:00", "08:01:00"): "NORMAL_DAY",
            ("11:00:00", "11:01:00"): "COOKING_MODE",
            ("13:00:00", "13:01:00"): "LUNCH_MODE",
            ("14:00:00", "14:01:00"): "NORMAL_DAY",
            ("15:00:00", "15:01:00"): "RELAX_MODE",
            ("17:00:00", "17:01:00"): "NORMAL_NIGHT_MODE",
            ("18:30:00", "18:31:00"): "COOKING_MODE",
            ("20:00:00", "20:01:00"): "DINNER_MODE",
            ("21:00:00", "21:01:00"): "RELAX_MODE",
            ("22:30:00", "22:31:00"): None
        }

        for (start, end), mode in time_modes.items():
            if start <= current_time < end:
                if mode:
                    requests.post('http://localhost:5000/set_mode',
                                data={'modeType': mode, 'status': 'on'})
                else:
                    requests.post('http://localhost:5000/set_mode',
                                data={'modeType': 'MEETING_MODE', 'status': 'off'})
                break

        sleep(30)

    logger.debug('Auto Light Mode thread stopped')

def airconditionerMode(fanLevel, length, everyTimeMinute, repeat, waterPump, betweenChannelPump):
    """Automatic air conditioner control with scheduling"""
    global airConditioner_mode_enabled, isAutoAirconditionerOn

    logger.debug("AC Auto thread started")

    length = int(length)
    everyTimeMinute = int(everyTimeMinute)

    while airConditioner_mode_enabled:
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=length)

        while datetime.now() < end_time and airConditioner_mode_enabled:
            isAutoAirconditionerOn = True

            pump_pin = pinToType["Cooler_Pump"]
            GPIO.setup(pump_pin, GPIO.OUT, initial=GPIO.HIGH)
            GPIO.output(pump_pin, GPIO.LOW if waterPump.lower() == "on" else GPIO.HIGH)

            fan_pin = pinToType["Fan_Between_Channels_Switch"]
            GPIO.setup(fan_pin, GPIO.OUT, initial=GPIO.HIGH)
            GPIO.output(fan_pin, GPIO.HIGH if betweenChannelPump.lower() == "on" else GPIO.LOW)

            cooler_pin = pinToType["CoolerPower"]
            GPIO.setup(cooler_pin, GPIO.OUT, initial=GPIO.HIGH)
            GPIO.output(cooler_pin, GPIO.LOW)

            requests.post('http://localhost:5000/set_airconditioner',
                        data={'fanLevel': fanLevel, 'waterPumpStatus': 'off', 'tempSet': '0'})

            sleep(30)

        isAutoAirconditionerOn = False
        logger.debug('AC cycle complete, turning off')

        requests.post('http://localhost:5000/set_airconditioner',
                    data={'fanLevel': '0', 'waterPumpStatus': 'off', 'tempSet': '0'})
        sleep(1)

        GPIO.output(pinToType["CoolerPower"], GPIO.HIGH)
        GPIO.output(pinToType["Fan_Between_Channels_Switch"], GPIO.LOW)
        GPIO.output(pinToType["Cooler_Pump"], GPIO.HIGH)

        if repeat.lower() == "off":
            logger.debug('No repeat, stopping AC')
            break

        logger.debug(f'Waiting {everyTimeMinute} minutes before next cycle')
        sleep(everyTimeMinute * 60)

    isAutoAirconditionerOn = False
    GPIO.output(pinToType["CoolerPower"], GPIO.HIGH)
    GPIO.output(pinToType["Fan_Between_Channels_Switch"], GPIO.LOW)
    GPIO.output(pinToType["Cooler_Pump"], GPIO.HIGH)
    logger.debug('AC Auto thread stopped')

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
    while True:
        success, frame = cap.read()
        if not success:
            break
        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

@app.route('/video_feed/<int:stream_id>')
@login_required
def video_feed(stream_id):
    return Response(generate_frames(rtsp_streams[stream_id]),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

# =======================
# DATE AND WEATHER API
# =======================
@app.route("/get_date_weather", methods=['GET'])
@login_required
def get_date_weather():
    """Return current date and weather information"""
    now = datetime.now()
    
    gregorian_date = now.strftime("%A, %B %d, %Y")
    
    j_date = jdatetime.datetime.now()
    shamsi_months = {
        1: 'فروردین', 2: 'اردیبهشت', 3: 'خرداد', 4: 'تیر',
        5: 'مرداد', 6: 'شهریور', 7: 'مهر', 8: 'آبان',
        9: 'آذر', 10: 'دی', 11: 'بهمن', 12: 'اسفند'
    }
    shamsi_weekdays = {
        0: 'دوشنبه', 1: 'سه‌شنبه', 2: 'چهارشنبه', 3: 'پنج‌شنبه',
        4: 'جمعه', 5: 'شنبه', 6: 'یکشنبه'
    }
    
    shamsi_date = f"{shamsi_weekdays[j_date.weekday()]}، {j_date.day} {shamsi_months[j_date.month]} {j_date.year}"
    
    hour = now.hour
    if 5 <= hour < 12:
        time_of_day = "morning"
    elif 12 <= hour < 17:
        time_of_day = "noon"
    elif 17 <= hour < 20:
        time_of_day = "afternoon"
    else:
        time_of_day = "night"
    
    weather_data = get_live_weather()
    
    return jsonify({
        "gregorian": gregorian_date,
        "shamsi": shamsi_date,
        "time": now.strftime("%H:%M"),
        "timeOfDay": time_of_day,
        "weather": weather_data
    })

def get_live_weather():
    """Fetch live weather data from OpenWeatherMap API"""
    
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
        icon = weather_icons.get(main_weather, "🌤️")
        
        weather_info = {
            "temperature": round(data['main']['temp']),
            "feels_like": round(data['main']['feels_like']),
            "humidity": data['main']['humidity'],
            "wind_speed": round(data['wind']['speed'] * 3.6),
            "description": data['weather'][0]['description'].title(),
            "icon": icon,
            "temp_min": round(data['main']['temp_min']),
            "temp_max": round(data['main']['temp_max']),
            "pressure": data['main']['pressure'],
            "visibility": round(data.get('visibility', 0) / 1000, 1),
            "clouds": data['clouds']['all']
        }
        
        logger.info(f"Weather data fetched successfully: {weather_info['temperature']}°C")
        return weather_info
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching weather data: {e}")
        
        return {
            "temperature": 18, "feels_like": 16, "humidity": 45, "wind_speed": 12,
            "description": "Weather Unavailable", "icon": "🌤️", "temp_min": 12,
            "temp_max": 22, "pressure": 1013, "visibility": 10, "clouds": 20
        }
    except KeyError as e:
        logger.error(f"Error parsing weather data: {e}")
        
        return {
            "temperature": 18, "feels_like": 16, "humidity": 45, "wind_speed": 12,
            "description": "Weather Unavailable", "icon": "🌤️", "temp_min": 12,
            "temp_max": 22, "pressure": 1013, "visibility": 10, "clouds": 20
        }

# =======================
# MAIN
# =======================
if __name__ == "__main__":
    logger.info("Initializing system - turning off all lights")
    for pin in AllLights:
        set_pin_state(pin, False)

    logger.info("Starting Flask server on port 5000")
    app.run(host='0.0.0.0', debug=False, port=5000)
