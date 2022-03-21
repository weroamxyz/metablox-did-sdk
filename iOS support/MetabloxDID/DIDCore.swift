//
//  DIDSwift.swift
//  did_demo
//
//  Created by TORA on 2022-03-14.
//

import Foundation
import MetabloxDID.DID
import UIKit

public class DIDCore {
    private let storePath: URL
    private let walletHandlerPtr: UnsafeMutableRawPointer
    private var loadedDIDPtr: UnsafeMutableRawPointer? = nil
    
    deinit {
        
    }
    
    // Initialize a DIDCore instance by providing a local file path for storage of database
    public init?(storePath: URL) {
        self.storePath = storePath
        
        let name = "DIDStore"
        self.walletHandlerPtr = wallet_handle_create(name, storePath.path)
    }
    
    // Create a DID record stored in store path, tagged with 'name' and encrypted with 'passcode'.
    @discardableResult
    public func createDID(name: String, passcode: String)-> Bool {
        guard let newDidPtr = did_create("secp256k1", nil) else {return false}
        wallet_store_did(self.walletHandlerPtr, newDidPtr, name, passcode)
        return true
    }
    
    // Load the DID from storage using 'name' and 'passcode' for decryption
    @discardableResult
    public func loadDID(name: String, passcode:String)-> Bool {
        guard let did = wallet_load_did(self.walletHandlerPtr, name, passcode) else {return false}
        self.loadedDIDPtr = did
        return true
    }
    
    // Read DID Document from currently loaded DID, formated in JSON string.
    public func readDIDDoc()-> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: 2048)
        did_serialize(did, buffer, 2048)
        let serializedDoc = String(cString: buffer, encoding: .utf8)
        //buffer.deallocate()
        return serializedDoc
    }
    
    private let DIDSignatureLength = 64
    // Sign a content string with the private key of DID and return signature
    public func signature(content: String)-> Data? {
        guard let did = self.loadedDIDPtr else {return nil}
        
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: DIDSignatureLength)
        did_sign(did, content, content.lengthOfBytes(using: .utf8), buffer, DIDSignatureLength)
        let sig = Data(bytes: buffer, count: DIDSignatureLength)
        //buffer.deallocate()
        return sig
    }
    
    // Verify the signature and unsigned content with the current DID public key.
    // Return: 0 = fail, 1 = pass, -1 = DIDError
    public func verifySignature(content: String, signature: Data, finishHandler:(Int)->()) {
        guard let did = self.loadedDIDPtr else {
            finishHandler(-1)
            return
        }
        
        let didMeta = did_to_did_meta(did)
        signature.withUnsafeBytes { (bytes: UnsafePointer<CChar>) in
            let result = did_verify(didMeta?.pointee.did_keys, content, content.lengthOfBytes(using: .utf8), bytes, DIDSignatureLength)
            finishHandler(Int(result))
        }
    }
}
 
