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
                print("!!! DID signature verify failure !!!")
                break
            case 1:
                print("--- DID signature verify pass ---")
                break
            default:
                print("!!! unknown return \(result) !!!")
                break
            }
            
            XCTAssert(result == 1, "DID signature verify failure")
        }
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
