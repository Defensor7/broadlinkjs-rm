import { EventEmitter } from 'events';
import { createSocket, Socket, RemoteInfo } from 'dgram';
import { networkInterfaces } from 'os';
import assert, { AssertionError } from 'assert';
import crypto from 'crypto';

function logBuffer(payload: Buffer) {
  for (let i = 0; i < payload.length; i += 16) {
    console.log([...payload.slice(i, i + 16)].map((b) => b.toString(16)));
  }
}

// RM Devices (without RF support)
const rmDeviceTypes = new Map([
  [0x2737, 'Broadlink RM Mini'],
  [0x27c7, 'Broadlink RM Mini 3 A'],
  [0x27c2, 'Broadlink RM Mini 3 B'],
  [0x27de, 'Broadlink RM Mini 3 C'],
  [0x5f36, 'Broadlink RM Mini 3 D'],
  [0x273d, 'Broadlink RM Pro Phicomm'],
  [0x2712, 'Broadlink RM2'],
  [0x2783, 'Broadlink RM2 Home Plus'],
  [0x277c, 'Broadlink RM2 Home Plus GDT'],
  [0x278f, 'Broadlink RM Mini Shate'],
]);

// RM Devices (with RF support)
const rmPlusDeviceTypes = new Map([
  [0x272a, 'Broadlink RM2 Pro Plus'],
  [0x2787, 'Broadlink RM2 Pro Plus v2'],
  [0x278b, 'Broadlink RM2 Pro Plus BL'],
  [0x2797, 'Broadlink RM2 Pro Plus HYC'],
  [0x27a1, 'Broadlink RM2 Pro Plus R1'],
  [0x27a6, 'Broadlink RM2 Pro PP'],
  [0x279d, 'Broadlink RM3 Pro Plus'],
  [0x27a9, 'Broadlink RM3 Pro Plus v2'], // (model RM 3422)
  [0x27c3, 'Broadlink RM3 Pro'],
]);

// RM4 Devices (without RF support)
const rm4DeviceTypes = new Map([
  [0x51da, 'Broadlink RM Mini 4'],
  [0x5f36, 'Broadlink RM Mini 3'],
  [0x610e, 'Broadlink RM Mini 4'],
  [0x62bc, 'Broadlink RM Mini 4'],
  [0x6070, 'Broadlink RM Mini 4 C'],
  [0x62be, 'Broadlink RM Mini 4 C'],
]);

// Known Unsupported Devices
const unsupportedDeviceTypes = new Map([
  [0, 'Broadlink SP1'],
  [0x2711, 'Broadlink SP2'],
  [0x2719, 'Honeywell SP2'],
  [0x7919, 'Honeywell SP2'],
  [0x271a, 'Honeywell SP2'],
  [0x791a, 'Honeywell SP2'],
  [0x2733, 'OEM Branded SP Mini'],
  [0x273e, 'OEM Branded SP Mini'],
  [0x2720, 'Broadlink SP Mini'],
  [0x7d07, 'Broadlink SP Mini'],
  [0x753e, 'Broadlink SP 3'],
  [0x2728, 'Broadlink SPMini 2'],
  [0x2736, 'Broadlink SPMini Plus'],
  [0x2714, 'Broadlink A1'],
  [0x4eb5, 'Broadlink MP1'],
  [0x2722, 'Broadlink S1 (SmartOne Alarm Kit)'],
  [0x4e4d, 'Dooya DT360E (DOOYA_CURTAIN_V2) or Hysen Heating Controller'],
  [0x4ead, 'Dooya DT360E (DOOYA_CURTAIN_V2) or Hysen Heating Controller'],
  [0x947a, 'BroadLink Outlet'],
]);

const allSupportedDevices = new Map([
  ...rmDeviceTypes,
  ...rmPlusDeviceTypes,
  ...rm4DeviceTypes,
]);

class Broadlink extends EventEmitter {
  log: (...args: any[]) => void;
  debug: boolean;

  devices: Map<Buffer, Device>;
  sockets: Array<Socket>;
  constructor(debug = false) {
    super();

    this.log = console.log;
    this.debug = debug;
    this.devices = new Map();
    this.sockets = [];
  }

  discover() {
    // Close existing sockets
    this.sockets.forEach((socket) => {
      socket.close();
    });

    this.sockets = [];

    // Open a UDP socket on each network interface/IP address
    const ipAddresses = this.getIPAddresses();

    ipAddresses.forEach((ipAddress) => {
      const socket = createSocket({ type: 'udp4', reuseAddr: true });
      this.sockets.push(socket);

      socket.on('listening', this.onListening.bind(this, socket, ipAddress));
      socket.on('message', this.onMessage.bind(this));

      socket.bind(0, ipAddress);
    });
  }

  getIPAddresses() {
    const interfaces = Object.values(networkInterfaces());

    return interfaces.reduce(
      (ipAddresses: Array<string>, interfaceInfos = []) => [
        ...ipAddresses,
        ...interfaceInfos
          .filter(({ family, internal }) => family === 'IPv4' && !internal)
          .map(({ address }) => address),
      ],
      []
    );
  }

  onListening(socket: Socket, ipAddress: string) {
    const { debug, log } = this;

    // Broadcase a multicast UDP message to let Broadlink devices know we're listening
    socket.setBroadcast(true);

    const splitIPAddress = ipAddress.split('.');
    const port = socket.address().port;
    if (debug && log)
      log(
        `\x1b[35m[INFO]\x1b[0m Listening for Broadlink devices on ${ipAddress}:${port} (UDP)`
      );

    const now = new Date();
    const starttime = now.getTime();

    const timezone = now.getTimezoneOffset() / -3600;
    const packet = Buffer.alloc(0x30, 0);

    const year = now.getFullYear() - 1900;

    if (timezone < 0) {
      packet[0x08] = 0xff + timezone - 1;
      packet[0x09] = 0xff;
      packet[0x0a] = 0xff;
      packet[0x0b] = 0xff;
    } else {
      packet[0x08] = timezone;
      packet[0x09] = 0;
      packet[0x0a] = 0;
      packet[0x0b] = 0;
    }

    packet[0x0c] = year & 0xff;
    packet[0x0d] = year >> 8;
    packet[0x0e] = now.getMinutes();
    packet[0x0f] = now.getHours();

    const subyear = year % 100;
    packet[0x10] = subyear;
    packet[0x11] = now.getDay();
    packet[0x12] = now.getDate();
    packet[0x13] = now.getMonth();
    packet[0x18] = parseInt(splitIPAddress[0]);
    packet[0x19] = parseInt(splitIPAddress[1]);
    packet[0x1a] = parseInt(splitIPAddress[2]);
    packet[0x1b] = parseInt(splitIPAddress[3]);
    packet[0x1c] = port & 0xff;
    packet[0x1d] = port >> 8;
    packet[0x26] = 6;

    let checksum = 0xbeaf;

    for (let i = 0; i < packet.length; i++) {
      checksum += packet[i];
    }

    checksum = checksum & 0xffff;
    packet[0x20] = checksum & 0xff;
    packet[0x21] = checksum >> 8;

    socket.send(packet, 0, packet.length, 80, '255.255.255.255');
  }

  onMessage(message: Buffer, host: RemoteInfo) {
    // Broadlink device has responded
    const macAddress = Buffer.alloc(6, 0);

    message.copy(macAddress, 0x00, 0x3d);
    message.copy(macAddress, 0x01, 0x3e);
    message.copy(macAddress, 0x02, 0x3f);
    message.copy(macAddress, 0x03, 0x3c);
    message.copy(macAddress, 0x04, 0x3b);
    message.copy(macAddress, 0x05, 0x3a);

    // Ignore if we already know about this device
    if (this.devices.has(macAddress)) return;

    const deviceType = message[0x34] | (message[0x35] << 8);

    // Create a Device instance
    this.addDevice(host, macAddress, deviceType);
  }

  addDevice(host: RemoteInfo, macAddress: Buffer, deviceType: number) {
    const { log, debug } = this;

    if (this.devices.has(macAddress)) return;

    const isHostObjectValid =
      typeof host === 'object' &&
      (host.port || host.port === 0) &&
      host.address;

    assert(
      isHostObjectValid,
      `createDevice: host should be an object e.g. { address: '192.168.1.32', port: 80 }`
    );
    assert(macAddress, `createDevice: A unique macAddress should be provided`);
    assert(
      deviceType,
      `createDevice: A deviceType from the rmDeviceTypes or rmPlusDeviceTypes list should be provided`
    );

    // Mark is at not supported by default so we don't try to
    // create this device again.
    // this.devices[macAddress] = 'Not Supported';

    // Ignore devices that don't support infrared or RF.
    if (unsupportedDeviceTypes.get(deviceType)) return null;
    if (deviceType >= 0x7530 && deviceType <= 0x7918) return null; // OEM branded SPMini2

    // If we don't know anything about the device we ask the user to provide details so that
    // we can handle it correctly.
    if (!allSupportedDevices.has(deviceType)) {
      log(
        `\n\x1b[35m[Info]\x1b[0m We've discovered an unknown Broadlink device. This likely won't cause any issues.\n\nPlease raise an issue in the GitHub repository (https://github.com/lprhodes/homebridge-broadlink-rm/issues) with details of the type of device and its device type code: "${deviceType.toString(
          16
        )}". The device is connected to your network with the IP address "${
          host.address
        }".\n`
      );

      return null;
    }

    const isRM4Device = rm4DeviceTypes.has(deviceType);
    const deviceClass = isRM4Device ? DeviceRM4 : Device;
    const device = new deviceClass(host, macAddress, deviceType, {
      log,
      debug,
    });

    this.devices.set(macAddress, device);

    // Authenticate the device and let others know when it's ready.
    device.on('deviceReady', () => {
      this.emit('deviceReady', device);
    });

    device.authenticate();
  }

  SECURITY_MODES = new Map([
    ['NONE', 0],
    ['WEP', 1],
    ['WPA1', 2],
    ['WPA2', 3],
    ['WPA1/2', 4],
  ]);

  setup(ssid: string, password: string, security: string) {
    assert(
      this.SECURITY_MODES.has(security),
      `security mode "${security}" must be one of ${[
        ...this.SECURITY_MODES.keys(),
      ]}`
    );

    const securityMode = this.SECURITY_MODES.get(security) || 0;

    const payload = Buffer.alloc(0x88);
    payload[0x26] = 0x14;
    payload.set(stringToBytes(ssid), 68);
    payload.set(stringToBytes(password), 100);
    payload.set([ssid.length, password.length, securityMode], 0x84);
    const checksum = payload.reduce(
      (checksum, byte) => (checksum + byte) & 0xffff,
      0xbeaf
    );
    payload[0x20] = checksum & 0xff; // Checksum 1 position
    payload[0x21] = checksum >> 8; // Checksum 2 position

    const socket = createSocket({ type: 'udp4', reuseAddr: true });
    socket.bind(() => {
      socket.setBroadcast(true);
      socket.send(
        payload,
        80,
        '255.255.255.255',
        (error: Error | null, bytes: number) => {
          assert(!error, `Can't set up. Error ${error}`);
          socket.close();
        }
      );
    });
  }
}

const stringToBytes = (string: string) =>
  [...string].map((charString) => {
    const char = charString.charCodeAt(0);
    assert(
      char,
      `Can't convert "${charString}" in string "${string}" to a byte.`
    );
    return char;
  });

class Device extends EventEmitter {
  host: RemoteInfo;
  mac: Buffer;
  type: number;
  model: string;
  count: number;
  key: Buffer;
  iv: Buffer;
  id: Buffer;
  socket: Socket;
  log: typeof console.log;
  debug: boolean;
  enterRFSweep: (() => void) | undefined;
  checkRFData: (() => void) | undefined;
  checkRFData2: (() => void) | undefined;

  constructor(
    host: RemoteInfo,
    macAddress: Buffer,
    deviceType: number,
    { log, debug }: { log: typeof console.log; debug: boolean }
  ) {
    super();
    this.host = host;
    this.mac = macAddress;
    this.log = log;
    this.debug = debug;
    this.type = deviceType;
    this.model = allSupportedDevices.get(deviceType) || 'Unknown';

    this.count = Math.random() & 0xffff;
    this.key = Buffer.from([
      0x09,
      0x76,
      0x28,
      0x34,
      0x3f,
      0xe9,
      0x9e,
      0x23,
      0x76,
      0x5c,
      0x15,
      0x13,
      0xac,
      0xcf,
      0x8b,
      0x02,
    ]);
    this.iv = Buffer.from([
      0x56,
      0x2e,
      0x17,
      0x99,
      0x6d,
      0x09,
      0x3d,
      0x28,
      0xdd,
      0xb3,
      0xba,
      0x69,
      0x5a,
      0x2e,
      0x6f,
      0x58,
    ]);
    this.id = Buffer.from([0, 0, 0, 0]);

    this.socket = createSocket({ type: 'udp4', reuseAddr: true });
    this.setupSocket();

    // Dynamically add relevant RF methods if the device supports it
    const isRFSupported = rmPlusDeviceTypes.has(deviceType);
    if (isRFSupported) this.addRFSupport();
  }

  // Create a UDP socket to receive messages from the broadlink device.
  setupSocket() {
    const { socket } = this;

    socket.on('message', (response) => {
      const encryptedPayload = Buffer.alloc(response.length - 0x38, 0);
      response.copy(encryptedPayload, 0, 0x38);

      const err = response[0x22] | (response[0x23] << 8);
      if (err != 0) return;

      const decipher = crypto.createDecipheriv(
        'aes-128-cbc',
        this.key,
        this.iv
      );
      decipher.setAutoPadding(false);

      let payload = decipher.update(encryptedPayload);

      const p2 = decipher.final();
      if (p2) payload = Buffer.concat([payload, p2]);

      if (!payload) return false;

      const command = response[0x26];

      if (command == 0xe9) {
        this.key = Buffer.alloc(0x10, 0);
        payload.copy(this.key, 0, 0x04, 0x14);

        this.id = Buffer.alloc(0x04, 0);
        payload.copy(this.id, 0, 0x00, 0x04);

        this.emit('deviceReady');
      } else if (command == 0xee || command == 0xef) {
        this.onPayloadReceived(err, payload);
      } else {
        console.log('Unhandled Command: ', command);
      }
    });

    socket.bind();
  }

  authenticate() {
    const payload = Buffer.alloc(0x50, 0);

    payload[0x04] = 0x31;
    payload[0x05] = 0x31;
    payload[0x06] = 0x31;
    payload[0x07] = 0x31;
    payload[0x08] = 0x31;
    payload[0x09] = 0x31;
    payload[0x0a] = 0x31;
    payload[0x0b] = 0x31;
    payload[0x0c] = 0x31;
    payload[0x0d] = 0x31;
    payload[0x0e] = 0x31;
    payload[0x0f] = 0x31;
    payload[0x10] = 0x31;
    payload[0x11] = 0x31;
    payload[0x12] = 0x31;
    payload[0x1e] = 0x01;
    payload[0x2d] = 0x01;
    payload[0x30] = 'T'.charCodeAt(0);
    payload[0x31] = 'e'.charCodeAt(0);
    payload[0x32] = 's'.charCodeAt(0);
    payload[0x33] = 't'.charCodeAt(0);
    payload[0x34] = ' '.charCodeAt(0);
    payload[0x35] = ' '.charCodeAt(0);
    payload[0x36] = '1'.charCodeAt(0);

    this.sendPacket(0x65, payload);
  }

  sendPacket(command: number, payload: Buffer, debug = false) {
    const { log, socket } = this;
    this.count = (this.count + 1) & 0xffff;

    let packet = Buffer.alloc(0x38, 0);

    packet[0x00] = 0x5a;
    packet[0x01] = 0xa5;
    packet[0x02] = 0xaa;
    packet[0x03] = 0x55;
    packet[0x04] = 0x5a;
    packet[0x05] = 0xa5;
    packet[0x06] = 0xaa;
    packet[0x07] = 0x55;
    packet[0x24] = 0x2a;
    packet[0x25] = 0x27;
    packet[0x26] = command;
    packet[0x28] = this.count & 0xff;
    packet[0x29] = this.count >> 8;
    packet[0x2a] = this.mac[5];
    packet[0x2b] = this.mac[4];
    packet[0x2c] = this.mac[3];
    packet[0x2d] = this.mac[2];
    packet[0x2e] = this.mac[1];
    packet[0x2f] = this.mac[0];
    packet[0x30] = this.id[0];
    packet[0x31] = this.id[1];
    packet[0x32] = this.id[2];
    packet[0x33] = this.id[3];

    let checksum = 0xbeaf;
    for (let i = 0; i < payload.length; i++) {
      checksum += payload[i];
      checksum = checksum & 0xffff;
    }

    const cipher = crypto.createCipheriv('aes-128-cbc', this.key, this.iv);
    payload = cipher.update(payload);

    packet[0x34] = checksum & 0xff;
    packet[0x35] = checksum >> 8;

    packet = Buffer.concat([packet, payload]);

    checksum = 0xbeaf;
    for (let i = 0; i < packet.length; i++) {
      checksum += packet[i];
      checksum = checksum & 0xffff;
    }
    packet[0x20] = checksum & 0xff;
    packet[0x21] = checksum >> 8;

    if (debug) log('\x1b[33m[DEBUG]\x1b[0m packet', packet.toString('hex'));

    socket.send(
      packet,
      0,
      packet.length,
      this.host.port,
      this.host.address,
      (err, bytes) => {
        if (debug && err) log('\x1b[33m[DEBUG]\x1b[0m send packet error', err);
        if (debug)
          log(
            '\x1b[33m[DEBUG]\x1b[0m successfuly sent packet - bytes: ',
            bytes
          );
      }
    );
  }

  onPayloadReceived(err: number, payload: Buffer) {
    const param = payload[0];

    const data = Buffer.alloc(payload.length - 4, 0);
    payload.copy(data, 0, 4);

    switch (param) {
      case 1: {
        const temp = (payload[0x4] * 10 + payload[0x5]) / 10.0;
        this.emit('temperature', temp);
        break;
      }
      case 4: {
        //get from check_data
        const data = Buffer.alloc(payload.length - 4, 0);
        payload.copy(data, 0, 4);
        this.emit('rawData', data);
        break;
      }
      case 26: {
        //get from check_data
        const data = Buffer.alloc(1, 0);
        payload.copy(data, 0, 0x4);
        if (data[0] !== 0x1) break;
        this.emit('rawRFData', data);
        break;
      }
      case 27: {
        //get from check_data
        const data = Buffer.alloc(1, 0);
        payload.copy(data, 0, 0x4);
        if (data[0] !== 0x1) break;
        this.emit('rawRFData2', data);
        break;
      }
    }
  }

  // Externally Accessed Methods

  checkData() {
    const packet = Buffer.alloc(16, 0);
    packet[0] = 4;
    this.sendPacket(0x6a, packet);
  }

  sendData(data: Buffer, debug = false) {
    let packet = Buffer.from([0x02, 0x00, 0x00, 0x00]);
    packet = Buffer.concat([packet, data]);
    this.sendPacket(0x6a, packet, debug);
  }

  enterLearning() {
    let packet = Buffer.alloc(16, 0);
    packet[0] = 3;
    this.sendPacket(0x6a, packet);
  }

  checkTemperature() {
    let packet = Buffer.alloc(16, 0);
    packet[0] = 1;
    this.sendPacket(0x6a, packet);
  }

  cancelLearn() {
    const packet = Buffer.alloc(16, 0);
    packet[0] = 0x1e;
    this.sendPacket(0x6a, packet);
  }
  addRFSupport() {
    this.enterRFSweep = () => {
      const packet = Buffer.alloc(16, 0);
      packet[0] = 0x19;
      this.sendPacket(0x6a, packet);
    };

    this.checkRFData = () => {
      const packet = Buffer.alloc(16, 0);
      packet[0] = 0x1a;
      this.sendPacket(0x6a, packet);
    };

    this.checkRFData2 = () => {
      const packet = Buffer.alloc(16, 0);
      packet[0] = 0x1b;
      this.sendPacket(0x6a, packet);
    };
  }
}

class DeviceRM4 extends Device {
  request_header: Array<number>;
  code_sending_header: Array<number>;

  constructor(
    host: RemoteInfo,
    macAddress: Buffer,
    deviceType: number,
    opts: { log: typeof console.log; debug: boolean }
  ) {
    super(host, macAddress, deviceType, opts);

    this.request_header = [0x04, 0x00];
    this.code_sending_header = [0xd0, 0x00];
  }

  checkData() {
    let packet = Buffer.alloc(16, 0);
    packet[0] = this.request_header[0];
    packet[1] = this.request_header[1];
    packet[2] = 0x04;
    this.sendPacket(0x6a, packet);
  }

  sendData(data: Buffer, debug = false) {
    let packet = Buffer.from(this.code_sending_header);
    packet = Buffer.concat([packet, Buffer.from([0x02, 0x00, 0x00, 0x00])]);
    packet = Buffer.concat([packet, data]);
    this.sendPacket(0x6a, packet, debug);
  }

  checkTemperature() {
    let packet = Buffer.alloc(16, 0);
    packet[0] = this.request_header[0];
    packet[1] = this.request_header[1];
    packet[2] = 0x24;
    this.sendPacket(0x6a, packet);
  }

  enterLearning() {
    let packet = Buffer.alloc(16, 0);
    packet[0] = this.request_header[0];
    packet[1] = this.request_header[1];
    packet[2] = 0x03;
    this.sendPacket(0x6a, packet);
  }

  cancelLearn() {
    let packet = Buffer.alloc(16, 0);
    packet[0] = this.request_header[0];
    packet[1] = this.request_header[1];
    packet[2] = 0x1e;
    this.sendPacket(0x6a, packet);
  }

  onPayloadReceived(_err: number, payload: Buffer) {
    const param = payload[0];

    const data = Buffer.alloc(payload.length - 4, 0);
    payload.copy(data, 0, 4);

    switch (param) {
      case 10: {
        const temp = (payload[0x6] * 10 + payload[0x7]) / 10.0;
        //const humidity = (payload[0x8] * 10 + payload[0x9]) / 10.0;
        this.emit('temperature', temp);
        break;
      }
      case 4: {
        //get from start ot stop learning
        break;
      }
      case 94: {
        //get data from learning
        const data = Buffer.alloc(payload.length - 4, 0);
        payload.copy(data, 0, 6);
        this.emit('rawData', data);
        break;
      }
    }
  }
}

export default Broadlink;
