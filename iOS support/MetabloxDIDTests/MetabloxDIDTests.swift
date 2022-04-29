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
        let didpass = "123456"
        print("=== Create new DID with name '\(didname)' ===")
        let createdFlag = didc.createDID(name: didname, passcode: didpass)
        XCTAssert(createdFlag == true, "DID create failed")
        let loadedFlag = didc.loadDID(name: didname, passcode: didpass)
        XCTAssert(loadedFlag == true, "DID load failed")
        print("=== Load DID with name '\(didname)' ===")
        
        let didDesc = didc.readDIDDesc()
        XCTAssert(didDesc != nil, "DID meta read failed")
        print(didDesc!)
        
        let firstDidStr = didc.readDIDString()
        print("DID string 1: " + firstDidStr!)
        XCTAssert(firstDidStr != nil, "DID string read faild")
        
        print("=== Sign content with DID ===")
        let content = "Who is the smartest person in the world?"
        print("Content: " + content)
        let sig = didc.signature(content: content)
        XCTAssert(sig != nil, "DID signature failed")
        
        print("Signature(Base64): " + sig!.base64EncodedString())
        print("=== Verify signature with DID ===")
        didc.verifySignature(content: content, signature: sig!) { result in
            switch result {
            case -1:
                print("!!! DID ERROR !!!")
                break
            case 0:
                print("--- DID signature verify pass ---")
                break
            default:
                print("!!! unknown return \(result) !!!")
                break
            }
            
            XCTAssert(result == 0, "DID signature verify failure")
        }
        
        // Export did1
        let privatekey1 = didc.exportPrivateKey(name: didname, password: didpass)
        XCTAssert(privatekey1 != nil, "DID privateKey export failure")
        print("PrivateKey exported: " + privatekey1!)
        
        // Import did2
        let didName2 = "DioDio"
        let didPass2 = "111111"
        
        let didImportResult = didc.importDID(name: didName2, password: didPass2, privateKey: privatekey1!)
        XCTAssert(didImportResult == true, "DID import failure")
        
        // Export did2
        let privatekey2 = didc.exportPrivateKey(name: didName2, password: didPass2)
        XCTAssert(privatekey2 != nil, "DID privateKey export failure")
        print("PrivateKey 2 exported: " + privatekey2!)
        XCTAssert(privatekey1 == privatekey2, "DID private keys not the same after import")
        
        let didStr2 = didc.readDIDString()
        print("DID string 2: " + didStr2!)
        XCTAssert(didStr2 == firstDidStr, "DID strings not the same after import")
        
        let didLoadResult2 = didc.loadDID(name: didName2, passcode: didpass)
        XCTAssert(didLoadResult2 == false, "DID pass not changed")
        
        // Change profile name
        let didName3 = "JoJo"
        let didPass3 = "4321"
        
        let changeNameResult = didc.changeProfileName(name: didName2, newName: didName3)
        XCTAssert(changeNameResult == true, "DID name change failure")
        let export3 = didc.exportPrivateKey(name: didName3, password: didPass2)
        XCTAssert(export3 != nil, "DID privateKey export failure after change name")
        
        // Change password
        let changePassResult = didc.changePassword(name: didName3, oldPassword: didPass2, newPassword: didPass3)
        XCTAssert(changePassResult == true, "DID pass change failure")
        let export4 = didc.exportPrivateKey(name: didName3, password: didPass3)
        XCTAssert(export4 != nil, "DID privateKey export failure after change pass")
        
        // Test namelist
        let namelist = didc.profileNameList()
        print("DID Profile namelist: \n\(namelist)")
        XCTAssert(namelist.count == 2, "DID namelist length not as expected")
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
