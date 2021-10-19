# Trackle library for Node.js

````
                     __     _         _ 
  _                 |    __| |       (_)   
 / |_  _ __ ___  ___|   / /| | ___    _  ___  
/_ __||  _/|__ \/ __|  / / | |/ _ \  | |/ _ \ 
 | |__| |  / _ | (__| /  \ | |  __/ _| | (_) |
  \__/|_|  \___/\___|/  \_\|_|\___|(_)_|\___/
````


[![GitHub version](https://img.shields.io/badge/version-v1.2.0-blue)](https://github.com/trackle-iot/trackle-nodejs-library/releases/latest) &nbsp; &nbsp;
[![GitHub stars](https://img.shields.io/github/stars/trackle-iot/trackle-nodejs-library?style=social)](https://github.com/trackle-iot/trackle-nodejs-library/stargazers) 
__________

## What is Trackle

Trackle is an IoT platform that offers all the software and services needed to develop an IoT solution from Device to Cloud. [Trackle website](https://www.trackle.io)

## Overview
This document provides step by step instructions to install the Trackle library for Node.js and connect your device to Trackle Cloud.
We suggest to use VS Code (Microsoft Visual Studio Code), one of the best IDE for Javascript.

### Supported OS
Trackle library for Node.js runs on any hardware supporting Node.js with Linux based OS. It works well on Raspbian as well.

### Download
**Trackle [Library for NodeJS](https://github.com/trackle-iot/trackle-nodejs-library/releases/latest)**

### Quickstart: Get a Device ID and a private key
* Create an account on Trackle Cloud (https://trackle.cloud)
* Open "My Devices" section from the drawer
* Click the button "Claim a device"
* Select the link "I don't have a device id", then Continue
* The Device Id will be shown on the screen and the private key file will be download with name xxxx.der where xxxx is Device ID
* If you prefer to use a PEM string in your code instead of load the .der file you need to run from command line:
```` 
openssl ec -in xxxx.der -inform DER -out xxx.pem -outform PEM
```` 
* You should copy the content of xxxx-pem file into your code

### Example project

Start with a new project cloning our **[example](https://github.com/trackle-iot/trackle-nodejs-example)**

### Documentation

Read the documentation on [Trackle docs](https://docs.trackle.io). Docs are still under development.
