//
//  MetabloxDIDTests.swift
//  MetabloxDIDTests
//
//  Created by TORA on 2022-03-21.
//

import XCTest
import MetabloxDID

class MetabloxDIDTests: XCTestCase {
    private var storeDir: URL? = nil
    
    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        self.storeDir = defaultStoreDir()
        if FileManager.default.fileExists(atPath: storeDir!.path) {
            try FileManager.default.removeItem(atPath: storeDir!.path)
        }
        
        createKeyStoreDir(storeDir!)
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        
    }

    func testDID() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        // Any test you write for XCTest can be annotated as throws and async.
        // Mark your test throws to produce an unexpected failure when your test encounters an uncaught error.
        // Mark your test async to allow awaiting for asynchronous code to complete. Check the results with assertions afterwards.
        
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        print("=== Initialized DID store ===")
        print(storeDir!.path)
        
        let didname = "PiuPiu"
        print("=== Create new DID with name '\(didname)' ===")
        let createdFlag = didc.createDID(name: didname)
        XCTAssert(createdFlag == true, "DID create failed")
        let loadedFlag = didc.loadDID(name: didname)
        XCTAssert(loadedFlag == true, "DID load failed")
        print("=== Load DID with name '\(didname)' ===")
        
        let didDesc = didc.readDIDDesc()
        XCTAssert(didDesc != nil, "DID meta read failed")
        print(didDesc!)
        
        let didPubkey = didc.readDIDPublicKey()
        XCTAssert(didPubkey != nil, "DID pubkey read failed")
        print("Public key: " + didPubkey!)
        
        let firstDidStr = didc.readDIDString()
        print("DID string 1: " + firstDidStr!)
        XCTAssert(firstDidStr != nil, "DID string read faild")
        
        print("=== Sign content with DID ===")
        let contentToSign = "3a4f827566f436bd96c2809d43329f2f8cf2997af8738f449988665526ce4ab0"
        let dataToSign = Data(hexString: contentToSign)!
        print("Content to sign: " + contentToSign)
        let sig = didc.signature(contentHash: dataToSign)
        XCTAssert(sig != nil, "DID signature failed")
        
        print("Signature(Base64): " + sig!.sig.base64EncodedString())
        print("R: \(sig!.r) " + "S: \(sig!.s) " + "V: \(sig!.v)")
        print("=== Verify signature with DID ===")
        let vr = didc.verifySignature(contentHash:dataToSign , signature: sig!.0)
        XCTAssert(vr, "DID signature verify failure")
        
        // Export did1
        let privatekey1 = didc.exportPrivateKey(name: didname)
        XCTAssert(privatekey1 != nil, "DID privateKey export failure")
        print("PrivateKey exported: " + privatekey1!)
        
        // Import did2
        let didName2 = "DioDio"
        
        let didImportResult = didc.importDID(name: didName2, privateKey: privatekey1!)
        XCTAssert(didImportResult == true, "DID import failure")
        
        // Export did2
        let privatekey2 = didc.exportPrivateKey(name: didName2)
        XCTAssert(privatekey2 != nil, "DID privateKey export failure")
        print("PrivateKey 2 exported: " + privatekey2!)
        XCTAssert(privatekey1 == privatekey2, "DID private keys not the same after import")
        
        let didStr2 = didc.readDIDString()
        print("DID string 2: " + didStr2!)
        XCTAssert(didStr2 == firstDidStr, "DID strings not the same after import")
        
        let didLoadResult2 = didc.loadDID(name: didName2)
        XCTAssert(didLoadResult2 == true, "DID pass not changed")
        
        // Change profile name
        let didName3 = "JoJo"
        
        let changeNameResult = didc.changeProfileName(name: didName2, newName: didName3)
        XCTAssert(changeNameResult == true, "DID name change failure")
        let export3 = didc.exportPrivateKey(name: didName3)
        XCTAssert(export3 != nil, "DID privateKey export failure after change name")
        
        // Test namelist
        let namelist = didc.profileNameList()
        print("DID Profile namelist: \n\(namelist)")
        XCTAssert(namelist.count == 2, "DID namelist length not as expected")
    }
    
    func testDIDImport() throws {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        print("=== Initialized DID store ===")
        print(storeDir!.path)
        
        let profileName = "Imported"
        let privateKey = "secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09"
        
        let didImportResult = didc.importDID(name: profileName, privateKey: privateKey)
        XCTAssert(didImportResult == true, "DID import failure")
        
        let pubkey = didc.readDIDPublicKey()
        XCTAssert(pubkey != nil, "DID pubkey export nil")
        print("Read pubkey: " + pubkey!)
        XCTAssert(pubkey == "0x77Cb9d48A0808c48E2C77F00ae8E26bd7A1E6415")
        
        let didStr = didc.readDIDString()
        print("Read did string: " + didStr!)
        XCTAssert(didStr == "Fdq53BKE7V7Dzt8mky2EGgxVsSA8rzQgJUxzgt3pUhmA")
        
        let profileName2 = "Imported2"
        let privateKey2 = "secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09"
        
        let didImportResult2 = didc.importDID(name: profileName2, privateKey: privateKey2)
        XCTAssert(didImportResult2 == true, "DID import failure")
        
        let namelist = didc.profileNameList()
        print(namelist)
        XCTAssert(namelist.count == 2)
    }
    
    func testDIDSign() throws {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        print("=== Initialized DID store ===")
        print(storeDir!.path)
        
        let profileName = "Imported"
        let privateKey = "secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09"
        
        let didImportResult = didc.importDID(name: profileName, privateKey: privateKey)
        XCTAssert(didImportResult == true, "DID import failure")
        
        let contentToSign = "3a4f827566f436bd96c2809d43329f2f8cf2997af8738f449988665526ce4ab0"
        let dataToSign = Data(hexString: contentToSign)!
        
        let sig = didc.signature(contentHash: dataToSign)
        XCTAssert(nil != sig)
        print(sig!.sig.hexString)
        XCTAssert(sig!.v == 0)
        XCTAssert(sig!.r.hexString == "cb7e5f6ea8acf5a8ade2f8a6f5491fe134b5bd31f6013c6877c6dcfb9d604f1d")
        XCTAssert(sig!.s.hexString == "6de7ade1d141143d93aa6a202705d16a8cf859d588b6cba33493046c9553bd5a")
    }
    
    func testVCAndVPConstruction() throws {
        let pubkey = "BGdZhu52Vj0rOtjcqxqIStzN3pweos4x6l8rjnSUKbqcxgio2y8DZmG0YGMTILPRXTgQwwKQxKaRBqhy9wD2dHY="
        let pubkeyBytes = Data(base64Encoded: pubkey)!.toBytesCopy()
        defer {
            pubkeyBytes.deallocate()
        }
        let vcp_c = new_vc_proof("EcdsaSecp256k1Signature2019", "2022-05-19T01:48:31Z", "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", "Authentication", nil, pubkeyBytes);
        XCTAssert(vcp_c != nil)
        let vcProof = CoreProofModel(vcProof: vcp_c!)
        XCTAssert(vcProof.JWSSignature == "")
        XCTAssert(vcProof.publicKey == pubkey)
        print(vcProof)
        let vcp_c_2 = vcProof.toVCProof()
        XCTAssert(vcp_c_2?.pointee.type != nil)
        let recoveredPubkey = Data(bytes: &vcp_c_2!.pointee.public_key.0, count: 65).base64EncodedString()
        XCTAssert(recoveredPubkey == pubkey)
        
        let context = ["https://www.w3.org/2018/credentials/v1","https://ns.did.ai/suites/secp256k1-2019/v1/"]
        let type = ["VerifiableCredential","MiningLicense"]
        let subject = ["did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
                       "TestName",
                       "TestModel",
                       "TestSerial"]
        let vc1 = VCCoreModel(context: context, id: "http://metablox.com/credentials/1", type: type, subType: "MiningLicense", issuer: "did:metablox:sampleIssuer", issuanceDate: "2022-05-19T01:48:31Z", expirationDate: "2032-05-19T01:48:31Z", description: "Example Wifi Access Credential", credentialSubject: subject, vcProof: vcProof, revoked: false)
        XCTAssert(vc1.context.count == 2)
        print(vc1)
        
        let vc1_c = vc1.toCStruct()
        XCTAssert(vc1_c != nil)
        XCTAssert(vc1_c?.pointee.vcProof != nil)
        XCTAssert(vc1_c?.pointee.count_context == 2)
        XCTAssert(vc1_c?.pointee.revoked == 0)
        let vc2 = VCCoreModel(vc: vc1_c!)
        XCTAssert(vc2.context.count == 2)
        XCTAssert(!vc2.vcProof.publicKey.isEmpty)
        print(vc2)
        
        let vpf_c = new_vp_proof("EcdsaSecp256k1Signature2019", "2022-05-19T01:48:31Z", "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification", "Authentication", nil, "0000", "vpPubkey");
        let vpf = CoreProofModel(vpProof: vpf_c!)
        
        let vp1 = VPCoreModel(context: context, type: type, vc: [vc1], holder: "did:metablox:sampleholder", vpProof: vpf)
        XCTAssert(vp1.context.count == 2)
        let vp1_c = vp1.toCStruct()
        XCTAssert(vp1_c?.pointee.vc != nil)
        let vp2 = VPCoreModel(vp: vp1_c!)
        XCTAssert(vp2.context.count == 2)
        XCTAssert(vp2.vc.count == 1)
        XCTAssert(!vp2.vc[0].vcProof.type.isEmpty)
        print(vp2)
        
    }
    
    func testGenerateAndSignVC() throws {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        
        let profileName = "Imported"
        let privateKey = "secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09"
        
        let didImportResult = didc.importDID(name: profileName, privateKey: privateKey)
        XCTAssert(didImportResult == true, "DID import failure")
        
        let id = "http://metablox.com/credentials/1"
        let specific_license = "MiningLicense"
        let description = "Mining License Credential"
        
        let vc = didc.generateVCAndSign(id, specific_license, description)
    
        XCTAssert(vc != nil)
        XCTAssert(vc!.context.count == 2)
        
        let pubKey = didc.readRawPublickeyInBase64()
        XCTAssert(vc!.vcProof.publicKey == pubKey)
        XCTAssert(vc!.type.count == 2)
        let verifyVCR = didc.verifyVC(vc!)
        XCTAssert(verifyVCR)
    }
    
    func testGenerateAndSignVP() throws {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        
        let profileName = "Imported"
        let privateKey = "secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09"
        
        let didImportResult = didc.importDID(name: profileName, privateKey: privateKey)
        XCTAssert(didImportResult == true, "DID import failure")
        
        let id = "http://metablox.com/credentials/1"
        let specific_license = "MiningLicense"
        let description = "Mining License Credential"
        
        let vc = didc.generateVCAndSign(id, specific_license, description)
        XCTAssert(vc != nil)
        XCTAssert(didc.verifyVC(vc!))
        
        let vp = didc.generateVPAndSign(vc: vc!, nonce: "123456")
        XCTAssert(vp != nil)
        XCTAssert(vp!.context.count == 2)
        XCTAssertEqual(vp!.vpProof.nonce, "123456")
        XCTAssert(didc.verifyVP(vp!))
    }
    
    func testVCAndVPVerify() throws {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        
        let profileName = "Imported"
        let privateKey = "secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09"
        
        let didImportResult = didc.importDID(name: profileName, privateKey: privateKey)
        XCTAssert(didImportResult == true, "DID import failure")
        
        let vcproof = CoreProofModel(type: "EcdsaSecp256k1Signature2019",
                                 created: "2022-05-27T02:33:24Z",
                                 verificationMethod: "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
                                 proofPurpose: "Authentication",
                                 publicKey: "BGdZhu52Vj0rOtjcqxqIStzN3pweos4x6l8rjnSUKbqcxgio2y8DZmG0YGMTILPRXTgQwwKQxKaRBqhy9wD2dHY=",
                                 JWSSignature: "eyJhbGciOiJFUzI1NiJ9..nkzhEKQQQrgrrrMBiFeiwP1wGKJ5NoXk2awh_HRq8c0WHtRF_mtjsSpMmJpf1v-3AIBrylTDtnfYSktQxbGToQ")
        let vc = VCCoreModel(context: ["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#", "https://www.w3.org/2018/credentials/v1"],
                             id: "http://metablox.com/credentials/97",
                             type: ["MiningLicense", "VerifiableCredential"],
                             subType: "",
                             issuer: "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
                             issuanceDate: "2022-05-27T02:26:08Z",
                             expirationDate: "2032-05-27T02:26:08Z",
                             description: "Example Mining License Credential",
                             credentialSubject: ["did:metablox:HNXrdVz8caA48HtyPMWcnBSCyuxfwSzZgPeDVQ2H9RcK", "", "", ""],
                             vcProof: vcproof,
                             revoked: false
                            )
        
        let verifyR = didc.verifyVC(vc)
        XCTAssert(verifyR)
        
        let vp = didc.generateVPAndSign(vc: vc, nonce: "123456")
        XCTAssert(vp != nil)
        XCTAssert(vp!.vc.count == 1)
        XCTAssert(vp!.vc.first?.vcProof.publicKey == "BGdZhu52Vj0rOtjcqxqIStzN3pweos4x6l8rjnSUKbqcxgio2y8DZmG0YGMTILPRXTgQwwKQxKaRBqhy9wD2dHY=")
        XCTAssert(vp!.type.count == 1)
        let verifyVR = didc.verifyVP(vp!)
        XCTAssert(verifyVR)
    }
    
    func testVCVerify2() throws {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        
        let profileName = "Imported"
        let privateKey = "secp256k1.eab9376db6d94b0dfdad84076f257d6bd1102344f3cd0332731cf1cd066cd2a0"
        
        let didImportResult = didc.importDID(name: profileName, privateKey: privateKey)
        XCTAssert(didImportResult == true, "DID import failure")
        
        let vcproof = CoreProofModel(type: "EcdsaSecp256k1Signature2019",
                                 created: "2022-05-31T06:35:51Z",
                                 verificationMethod: "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX#verification",
                                 proofPurpose: "Authentication",
                                 publicKey: "BGdZhu52Vj0rOtjcqxqIStzN3pweos4x6l8rjnSUKbqcxgio2y8DZmG0YGMTILPRXTgQwwKQxKaRBqhy9wD2dHY=",
                                 JWSSignature: "eyJhbGciOiJFUzI1NiJ9..VaDsrXG-hbjXDd9ALjVduSoBnbLuY-nvOA6ctFH7NUUF6NYzQiPTDcU50t1XnIrst9shuos-OqkpbRJDOwzb0Q")
        let vc = VCCoreModel(context: ["https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#", "https://www.w3.org/2018/credentials/v1"],
                             id: "http://metablox.com/credentials/102",
                             type: ["VerifiableCredential", "WifiAccess"],
                             subType: "",
                             issuer: "did:metablox:7rb6LjVKYSEf4LLRqbMQGgdeE8MYXkfS7dhjvJzUckEX",
                             issuanceDate: "2022-05-30T18:59:10Z",
                             expirationDate: "2032-05-30T18:59:10Z",
                             description: "Example Wifi Access Credential",
                             credentialSubject: ["did:metablox:GkcBPtjRsrVYBZChQpxCG6jBzfLGYzMsQjpwVXEQSeAW", "User"],
                             vcProof: vcproof,
                             revoked: false
                            )
        
        let verifyR = didc.verifyVC(vc)
        XCTAssert(verifyR)
        
        let vpModel = didc.generateVPAndSign(vc: vc, nonce: "11")
        
        let jsonData = try JSONEncoder().encode(vpModel!)
        let jsonString = String(data: jsonData, encoding: .utf8)!
        
        print ("Model data")
        print(jsonString)
    }

    func testVpVerify2() throws {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        
        let profileName = "Imported"
        let privateKey = "secp256k1.eab9376db6d94b0dfdad84076f257d6bd1102344f3cd0332731cf1cd066cd2a0"
        
        let didImportResult = didc.importDID(name: profileName, privateKey: privateKey)
        XCTAssert(didImportResult == true, "DID import failure")
        
        let vcproof = CoreProofModel(type: "EcdsaSecp256k1Signature2019",
                                 created: "2022-06-01T01:41:25-04:00",
                                 verificationMethod: "did:metablox:V612aF8NKhDm2KEq9V43WhemArcRnx5LvxK35fQyzmX#verification",
                                 proofPurpose: "Authentication",
                                 publicKey: "BKdG5rdV8sjkBKiBG+f0O2NGeKmcYXGVHrOWLVe343UMxPb1w/kvvK7r8z5sITjXkoBwQBpy0oa2sb5qy9k656Q=",
                                 JWSSignature: "eyJhbGciOiJFUzI1NiJ9..lRfECEA4W6z4tJfO4ctMab0fSHzppGju2yQKfjDaudYjSQ6rEoN9jO8hOhuvP1vlTqOptaLEzI5sr9ElmaEbCw")
        let vc = VCCoreModel(context: ["https://www.w3.org/2018/credentials/v1","https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#"],
                             id: "http://metablox.com/credentials/1",
                             type: ["VerifiableCredential", "MiningLicense"],
                             subType: "",
                             issuer: "did:metablox:V612aF8NKhDm2KEq9V43WhemArcRnx5LvxK35fQyzmX",
                             issuanceDate: "2022-06-01 05:41:25",
                             expirationDate: "2032-06-01 05:41:25",
                             description: "MiningLicenseCredential",
                             credentialSubject: ["did:metablox:7w3VndqhPNrf5yzVfZnwTiGrctYULdRdnsEVZ5Zt5YWa", "Test", "test", "test"],
                             vcProof: vcproof,
                             revoked: false
                            )
        
        let verifyR = didc.verifyVC(vc)
        XCTAssert(verifyR)
        
        
        let vpproof = CoreProofModel(type: "EcdsaSecp256k1Signature2019",
                                 created: "2022-06-01T14:00:21+08:00",
                                 verificationMethod: "did:metablox:7w3VndqhPNrf5yzVfZnwTiGrctYULdRdnsEVZ5Zt5YWa#verification",
                                 proofPurpose: "Authentication",
                                 publicKey: "BBMnHMAZHT8T1aTogPqyXfO6tsf/mvnpN212NYg6nQuc2rSQPi4ITOT/ANHBfpdnMaLrIl+Wx2neDtuR22wlaRA=",
                                 JWSSignature: "eyJhbGciOiJFUzI1NiJ9..IujdBxE2avjFB6c5LMZBUyoEZNn6x8u4LXm3YhZth-EJQNqQPtHTQhMH7Jvt5Mjx_v8xeTekhhlI0oVfWPY7kQ",
                                 nonce: "1")
        
        let vp = VPCoreModel(context: ["https://www.w3.org/2018/credentials/v1","https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#"], type: ["VerifiablePresentation"], vc: [vc], holder: "did:metablox:7w3VndqhPNrf5yzVfZnwTiGrctYULdRdnsEVZ5Zt5YWa", vpProof: vpproof)
        let verifyVP = didc.verifyVP(vp)
        XCTAssert(verifyVP)
    }
    
    func testDIDDocument() {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!!DID store init fail!!!")
        let didc = didCore!
        print("=== Initialized DID store ===")
        print(storeDir!.path)
        
        let didname = "PiuPiu"
        print("=== Create new DID with name '\(didname)' ===")
        let createdFlag = didc.createDID(name: didname)
        XCTAssert(createdFlag == true, "DID create failed")
        let loadedFlag = didc.loadDID(name: didname)
        XCTAssert(loadedFlag == true, "DID load failed")
        print("=== Load DID with name '\(didname)' ===")
        
        let didDoc = didc.generateDIDDocument()
        XCTAssert(didDoc != nil, "DID Document created failed")
        XCTAssert(didDoc?.context.count == 2)
        XCTAssert(!didDoc!.id.isEmpty)
        XCTAssert(!didDoc!.created.isEmpty)
        XCTAssert(!didDoc!.updated.isEmpty)
        XCTAssert(didDoc?.version == 1.0)
        XCTAssert(!didDoc!.verificationMethod.first!.id.isEmpty)
        XCTAssert(didDoc?.verificationMethod.first!.type == "EcdsaSecp256k1VerificationKey2019")
        XCTAssert(!didDoc!.verificationMethod.first!.controller.isEmpty)
        XCTAssert(!didDoc!.verificationMethod.first!.publicKeyMultibase.isEmpty)
        XCTAssert(!didDoc!.authentication.isEmpty)
        
    }
    
    func testGenerateAndSignQOS() throws {
        let didCore = DIDCore(storePath: storeDir!)
        XCTAssert(didCore != nil, "!!! DID store init fail !!!")
        let didc = didCore!
        
        let profileName = "Imported"
        let privateKey = "secp256k1.2e6ad25111f09beb080d556b4ebb824bace0e16c84336c8addb0655cdbaade09"
        
        let didImportResult = didc.importDID(name: profileName, privateKey: privateKey)
        XCTAssert(didImportResult == true, "DID import failure")
        
        let qosObj = QOSCoreModel(bandwidth: "_123123asfakj", rssi: "", packetLose: "", nonce: "", jws: "")
        let qos = didc.generateQOSAndSign(nonce: qosObj.nonce, bandwidth: qosObj.bandwidth, rssi: qosObj.rssi, packetLose: qosObj.packetLose, jws: qosObj.jwsSignature);
        
        XCTAssert(qos != nil)
        XCTAssertFalse(qos!.jwsSignature.isEmpty)
        
        print(qos!.jwsSignature)
    }
    
    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }
    
    private func defaultStoreDir()->URL? {
        do {
            let docDir = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: false)
            return docDir.appendingPathComponent("DIDTest")
        } catch {
            print(error)
        }
        return nil
    }
    
    private func createKeyStoreDir(_ dir:URL) {
        let fileManager = FileManager.default
        try? fileManager.removeItem(at: dir)
        try? fileManager.createDirectory(at: dir, withIntermediateDirectories: true, attributes: nil)
    }

}

extension Data {
    var hexString: String {
        return map({ String(format: "%02x", $0) }).joined()
    }
    
    /// Initializes `Data` with a hex string representation.
    init?(hexString: String) {
        let string: String
        if hexString.hasPrefix("0x") {
            string = String(hexString.dropFirst(2))
        } else {
            string = hexString
        }

        // Check odd length hex string
        if string.count % 2 != 0 {
            return nil
        }

        // Check odd characters
        if string.contains(where: { !$0.isHexDigit }) {
            return nil
        }

        // Convert the string to bytes for better performance
        guard let stringData = string.data(using: .ascii, allowLossyConversion: true) else {
            return nil
        }

        self.init(capacity: string.count / 2)
        let stringBytes = Array(stringData)
        for i in stride(from: 0, to: stringBytes.count, by: 2) {
            guard let high = Data.value(of: stringBytes[i]) else {
                return nil
            }
            if i < stringBytes.count - 1, let low = Data.value(of: stringBytes[i + 1]) {
                append((high << 4) | low)
            } else {
                append(high)
            }
        }
    }
    
    /// Converts an ASCII byte to a hex value.
    private static func value(of nibble: UInt8) -> UInt8? {
        guard let letter = String(bytes: [nibble], encoding: .ascii) else { return nil }
        return UInt8(letter, radix: 16)
    }

    /// Reverses and parses hex string as `Data`
    static func reverse(hexString: String) -> Data {
        guard let data = Data(hexString: hexString) else { return Data() }
        return Data(data.reversed())
    }
}

extension StringProtocol {
    var hexa: [UInt8] {
        var startIndex = self.startIndex
        return (0..<count/2).compactMap { _ in
            let endIndex = index(after: startIndex)
            defer { startIndex = index(after: endIndex) }
            return UInt8(self[startIndex...endIndex], radix: 16)
        }
    }
}
