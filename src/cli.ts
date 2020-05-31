#!/usr/bin/env node

import process from 'process';
import assert from 'assert';
import Broadlink from './index';
const [bin, file, ssid, password, securityMode] = process.argv;
const message = `
usage: ${bin} ${file} SSID PASSWORD SECURITY_MODE

Note: Put the device in pairing mode and connect to it's wifi.
`;

assert(ssid && password && securityMode, message);
const broadlink = new Broadlink();
broadlink.setup(ssid, password, securityMode);
