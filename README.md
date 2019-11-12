# Fabric_CA_Simple

■ 참조 사이트 : https://medium.com/@kctheservant/exploring-fabric-ca-registration-and-enrollment-1b9f4a1b3ace

< Fabric-CA: Registration and Enrollment >
- Hyperledger Fabric은 허가 된 블록 체인 플랫폼입니다. 패브릭 네트워크와 상호 작용하려면 먼저 식별하고 권한을 부여 받아야합니다. 
- ID는 디지털 인증서로 구현되므로 인증서 관리를 처리하려면 인증 기관(CA)이 필요합니다.
- Fabcar의 enrollAdmin.js와 registerUser.js의 두 코드 는 Fabric-CA에 enrollment 및 registration.

1. Fabric Network 설정
- 네트워크 구동 후 Org1의 Fabric-CA에 중점을 둡니다.
- (그림 참조) ca_peerOrg1 and the two codes for enrollment and registration (enrollAdmin.js and registerUser.js) 두 파일의 코드 내용을 살펴봅니다.
$ cd fabric-samples/fabcar
$ ./startFabric.sh

2. Codes for Enrollment and Registration
- Fabric-CA와 상호 작용하는 두 가지 프로세스가 존재
- Enrollment : 사용자가 지정된 CA에 디지털 인증서를 요청하고 얻는 프로세스
- Registration  : 일반적으로 등록 기관에서 수행하며 CA에 디지털 인증서를 발급하도록 지시함.

2.1 디지털 인증서를 사용자에게 발급하는 3단계

2.1.1 1단계
- An admin(registrar) is enrolled to the CA
- admin receives the signing key and certificate for this admin (wallet/admin directory 생성됨)

2.1.2 2단계
- 관리자 는 적절한 정보를 사용하여 user1 을 CA에 등록
- CA returns with a secret.

2.1.3 3단계
- secret를 이용해서 user1를 the CA에 enroll 진행
- The result : user1의 signing key and certificate 생성

2.1.4 파일 역활(그림참조)
- 1단계 수행 파일 : enrollAdmin.js
- 2, 3단계 수행 파일 : registerUser.js 

3. 코드 재작업
3.1 enrollAdmin.js
- 코드 변경 없이 그대로 사용
- docker-compose-ca.yaml(파일 위치 => fabric-samples/first-network/) 내의 the default bootstrap administrator(admin : adminpw) 내용 그대로 사용

3.2 registerUser.js 를 두개(regUser.js/enrollUser.js) 부분으로 나누어서 설명 (그림참조 : Code rewritten to show the three steps clearer)
- the difference between registration and enrollment of a user. 구분해서 이해가 필요.
- 수행주체의 구분이 명확해야함.
: registration is done by a registrar (admin)
: enrollment of a user is done by the user with the secret given
- hardcoded 부분의 이해를 도움

3.2.1 regUser.js
- the enrollment ID 정보가 필요.
$ node regUser.js <enrollmentID>

############# regUser.js Code ###############
/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { FileSystemWallet, Gateway, X509WalletMixin } = require('fabric-network');
const path = require('path');

const ccpPath = path.resolve(__dirname, '..', '..', 'first-network', 'connection-org1.json');

async function main() {
    try {

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

	const user = process.argv[2];

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists(user);
        if (userExists) {
            console.log('An identity for the user ' + user + ' already exists in the wallet');
            return;
        }

        // Check to see if we've already enrolled the admin user.
        const adminExists = await wallet.exists('admin');
        if (!adminExists) {
            console.log('An identity for the admin user "admin" does not exist in the wallet');
            console.log('Run the enrollAdmin.js application before retrying');
            return;
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'admin', discovery: { enabled: true, asLocalhost: true } });

        // Get the CA client object from the gateway for interacting with the CA.
        const ca = gateway.getClient().getCertificateAuthority();
        const adminIdentity = gateway.getCurrentIdentity();

        // Register the user, enroll the user, and import the new identity into the wallet.
        const secret = await ca.register({ affiliation: 'org1.department1', enrollmentID: user, role: 'client' }, adminIdentity);
        console.log('Successfully registered user ' + user + ' and the secret is ' + secret );

    } catch (error) {
        console.error(`Failed to register user ${user}: ${error}`);
        process.exit(1);
    }
}

main();
############# regUser.js Code ###############

3.2.2 enrollUser.js
- requires two arguments : the enrollment ID & the secret
$ node enrollUser.js <enrollmentID> <secret>

############# enrollUser.js Code ###############
/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const FabricCAServices = require('fabric-ca-client');
const { FileSystemWallet, X509WalletMixin } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const ccpPath = path.resolve(__dirname, '..', '..', 'first-network', 'connection-org1.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

async function main() {
    try {

        // Create a new CA client for interacting with the CA.
        const caInfo = ccp.certificateAuthorities['ca.org1.example.com'];
        const caTLSCACerts = caInfo.tlsCACerts.pem;
        const ca = new FabricCAServices(caInfo.url, { trustedRoots: caTLSCACerts, verify: false }, caInfo.caName);

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

	const user = process.argv[2];
	const secret = process.argv[3];

        // Check to see if we've already enrolled the admin user.
        const userExists = await wallet.exists(user);
        if (userExists) {
            console.log('An identity for this user already exists in the wallet');
            return;
        }

        // Enroll the admin user, and import the new identity into the wallet.
        const enrollment = await ca.enroll({ enrollmentID: user, enrollmentSecret: secret });
        const identity = X509WalletMixin.createIdentity('Org1MSP', enrollment.certificate, enrollment.key.toBytes());
        await wallet.import(user, identity);
        console.log(`Successfully enrolled user ${user} and imported it into the wallet`);

    } catch (error) {
        console.error(`Failed to enroll admin user "admin": ${error}`);
        process.exit(1);
    }
}

main();
############# enrollUser.js Code ###############

4. Demonstration
- how to run these three scripts to register and enroll user1 for Fabcar application.

4.1 Run fabcar/startFabric.sh and make sure wallet is empty
$ cd fabric-samples/fabcar
$ ./startFabric.sh
$ cd javascript
$ rm -rf wallet

4.2 Install the required modules (Skip 가능)
$ npm install

4.3: Install sqlite3 in CA of org1
- Open another terminal.
$ docker exec -it ca_peerOrg1 bash

- Install the sqlite3 in ca_peerOrg1.
$ apt-get update
$ apt-get install sqlite3

- Fabric-CA 데이터베이스 : /etc/hyperledger/fabric-ca-server/fabric-ca-server.db
$ cd /etc/hyperledger/fabric-ca-server$ sqlite3 fabric-ca-server.db

- command line shell of sqlite.
sqlite> .tables
sqlite> select * from users;
sqlite> select * from certificates;

4.4 Enroll the Admin (Registrar)
- 관리자 를 등록하여 에 저장된 관리자의 서명 키와 인증서를 얻습니다 (wallet/admin.)
$ node enrollAdmin.js

- CA에서 users 테이블 을 다시 확인하십시오.
$ sqlite> select * from users;

- admin 의 필드가 0에서 1로 변경된 것을 볼 수 있습니다. 인증서가 발급되었음을 의미합니다.
- 인증서를 확인합니다.
$ sqlite> select * from certificates;

- 실제 인증서와 DB의 인증서를 비교합니다.
$ cat wallet/admin/admin

4.5 Register user1 into CA
$ node regUser.js user1
- Result => $Successfully registered user user1 and the secret is zlSAoyeAQXlP
- 아직 user1에 대한 새로운 지갑이 없습니다.

4.5.1 DB에서 현재 상황파악.
- user1가 users table 들어 있음을 확인하십시오. (아직 certificate는 생성되지 않았음)
$ sqlite> select * from users;
- the state is 0 for user1 : certificate는 생성되지 않았음을 의미함.

4.5.2 Enroll user1 and obtain the signing key and certificate
$ node enrollUser.js user1 zlSAoyeAQXlP
- Result : Successfully enrolled user user1 and imported it into the wallet (the signing key and certificate 생성됨)

4.5.2 DB에서 현재 상황파악.
$ sqlite> select * from certificates where id='user1';
- Result : 인증서 내용이 보임.

$ sqlite> select * from users where id='user1';
- Result : the state is changed to 1 ( 0 => 1)

4.6 Run the Fabcar scripts (user1 계정으로 query.js 실행 - 주의 : query.js 코드안에 user1 하드코딩되어 있음)
$ node query.js

4.7 user1 지갑을 잃어버렸을 경우 재발급 받는 Case
4.7.1 지갑을 삭제.
~javascript$ rm -r wallet/user1

4.7.2 동일한 secret 값으로 user1을 enroll 진행함
$ node enrollUser.js user1 zlSAoyeAQXlP
- Result : Failed to enroll admin user "admin": Error: Enrollment failed with errors [[{"code":20,"message":"Authentication failure"}]]

4.7.3 Fabric-CA database 수정해서 등록하는 방안(Tip !)
- 인증서 테이블 에서 user1 을 제거한 다음 users 테이블 에서 user1 의 상태 를 1에서 0으로 변경.
sqlite> delete from certificates where id='user1';
sqlite> update users set state=0 where id='user1';

$ node enrollUser.js user1 zlSAoyeAQXlP
- Result : Successfully enrolled user user1 and imported it into the wallet

5. CA Server Clean Up
$ sqlite> .exit
$ exit

6. Fabcar and First-Network Clean Up
$ cd fabric-samples/first-network
$ ./byfn.sh down
$ docker rm $(docker ps -aq)
$ docker rmi $(docker images dev-* -q)
