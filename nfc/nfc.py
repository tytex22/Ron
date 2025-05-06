import serial

# Replace this with your actual port
ser = serial.Serial('/dev/ttyUSB0', 9600)

print("Waiting for tag...")

while True:
    try:
        line = ser.readline().decode('utf-8').strip()
        if line:
            print("RFID Tag:", line)
    except KeyboardInterrupt:
        print("Exiting...")
        break
