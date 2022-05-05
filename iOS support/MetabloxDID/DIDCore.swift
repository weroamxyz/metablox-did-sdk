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
        return self.storeDID(didPtr: newDidPtr, name: name, passcode: passcode)
    }
    
    private func storeDID(didPtr: UnsafeMutableRawPointer, name: String, passcode: String)-> Bool {
        // Use MD5 for password bit length complement
        let pass = passcode.MD5()
        let result = wallet_store_did(self.walletHandlerPtr, didPtr, name, pass)
        guard result > 0 else {
            return false
        }
        return true
    }
    
    // Load the DID from storage using 'name' and 'passcode' for decryption
    @discardableResult
    public func loadDID(name: String, passcode:String)-> Bool {
        // Use MD5 for password bit length complement
        let pass = passcode.MD5()
        guard let did = wallet_load_did(self.walletHandlerPtr, name, pass) else {return false}
        self.loadedDIDPtr = did
        return true
    }
    
    public func readDIDString()-> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        guard let meta = did_to_did_meta(did) else {return nil}
        let DIDStr = String(cString: &meta.pointee.did.0, encoding: .utf8)
        return DIDStr
    }
    
    public func readDIDPublicKey()-> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        guard let meta = did_to_did_meta(did) else {return nil}
        let pubkey = String(validatingUTF8: &(meta.pointee.did_keys.pointee.publicKeyHex.0))
        return pubkey
    }
    
    // Read DID description from currently loaded DID, formated in JSON string.
    public func readDIDDesc()-> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: 2048)
        buffer.initialize(repeating: 0, count: 2048)
        did_serialize(did, buffer, 2048)
        let serializedDoc = String(cString: buffer, encoding: .utf8)
        defer {
            buffer.deinitialize(count: 2048)
            buffer.deallocate()
        }
        return serializedDoc
    }
    
    private let DIDSignatureLength = 65
    // Sign a content string with the private key of DID and return signature
    // Return format (sig, r, s, v)
    public func signature(content: String)-> (sig: Data, r: Data, s: Data, v: UInt8)? {
        guard let did = self.loadedDIDPtr else {return nil}
        
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: DIDSignatureLength)
        buffer.initialize(repeating: 0, count: DIDSignatureLength)
        did_sign(did, content, content.lengthOfBytes(using: .utf8), buffer, DIDSignatureLength)
        let sig = Data(bytes: buffer, count: DIDSignatureLength)
        
        defer {
            buffer.deinitialize(count: DIDSignatureLength)
            buffer.deallocate()
        }
        
        /*
          out  signature value
             out[0..31]  r
             out[32.63]  s
             out[64]     v
         */
        let r = sig.subdata(in: Range(0...31))
        let s = sig.subdata(in: Range(32...63))
        let v = sig[64]
        
        return (sig, r, s, v)
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
    
    private let DIDPrivateKeyLength = 65
    // Export private key string from a DID profile decrypting with password
    public func exportPrivateKey(name: String, password: String)-> String? {
        guard true == self.loadDID(name: name, passcode: password) else {
            return nil
        }
        
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: DIDPrivateKeyLength)
        buffer.initialize(repeating: 0, count: DIDPrivateKeyLength)
        let result = did_export_prikey(self.loadedDIDPtr, buffer)
        
        guard result == 0 else {
            return nil
        }
        
        let privateKeyStr = String(cString: buffer, encoding: .utf8)
        
        defer {
            buffer.deinitialize(count: DIDPrivateKeyLength)
            buffer.deallocate()
        }
        return privateKeyStr
    }
    
    // Import a DID profile with a profile name and a private key, encrypt with password, and then load it as current hold
    public func importDID(name: String, password: String, privateKey: String)-> Bool {
        guard let didPtr = did_import_privkey(privateKey) else {
            return false
        }
        
        guard true == self.storeDID(didPtr: didPtr, name: name, passcode: password) else {
            return false
        }
        
        return self.loadDID(name: name, passcode: password)
    }
    
    // Get profile name list from storage
    public func profileNameList() -> [String] {
        let nameListStruct = UnsafeMutablePointer<wallet_did_namelist>.allocate(capacity: 1)
        guard 0 == wallet_get_namelist(self.walletHandlerPtr, nameListStruct) else {
            return []
        }
        
        let listLength = Int(nameListStruct.pointee.count)
        var nameList: [String] = []
        for i in 0 ..< listLength {
            let name: String = String(cString: nameListStruct.pointee.names[i]!, encoding: .utf8)!
            nameList.append(name)
        }
        
        defer {
            nameListStruct.deallocate()
        }
        return nameList
    }
    
    // Change name of DID profile
    public func changeProfileName(name: String, newName: String) -> Bool {
        guard newName != name else {
            return true
        }
        
        guard 0 == wallet_change_name(self.walletHandlerPtr, name, newName) else {
            return false
        }
        
        return true
    }
    
    // Change password of DID profile
    public func changePassword(name: String, oldPassword: String, newPassword: String) -> Bool {
        guard oldPassword != newPassword else {
            return true
        }
        
        let oldPass = oldPassword.MD5()
        let newPass = newPassword.MD5()
        
        guard 0 == wallet_change_password(self.walletHandlerPtr, name, oldPass, newPass) else {
            return false
        }
        
        return true
    }
}


import CryptoKit

extension String {
    func MD5() -> String {
        let digest = Insecure.MD5.hash(data: self.data(using: .utf8) ?? Data())

        return digest.map {
            String(format: "%02hhx", $0)
        }.joined()
    }
}
 
