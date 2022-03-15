//
//  DIDSwift.swift
//  did_demo
//
//  Created by TORA on 2022-03-14.
//

import Foundation
import MetabloxDID.DID

public class DIDSwift {
    private let storePath: URL
    private let walletHandlerPtr: UnsafeMutableRawPointer
    private var loadedDIDPtr: UnsafeMutableRawPointer? = nil
    
    public init?(storePath: URL) {
        self.storePath = storePath
        
        let name = "DIDStore"
        self.walletHandlerPtr = wallet_handle_create(name, storePath.path)
    }
    
    public func createDID(name: String, passcode: String)-> Bool {
        guard let newDidPtr = did_create("secp256k1", nil) else {return false}
        wallet_store_did(self.walletHandlerPtr, newDidPtr, name, passcode)
        return true
    }
    
    public func loadDID(name: String, passcode:String)-> Bool {
        guard let did = wallet_load_did(self.walletHandlerPtr, name, passcode) else {return false}
        self.loadedDIDPtr = did
        return true
    }
    
    public func readDID()-> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        let didMeta: UnsafeMutablePointer<did_meta_tag> = did_to_did_meta(did)
        return String(cString: &didMeta.pointee.did.0, encoding: .utf8)
    }
}

extension String {
    fileprivate func charArrayPtr()-> UnsafePointer<Int8> {
        let cString = self.cString(using: .ascii)!
        let str: String = NSString(bytes: cString, length: self.count, encoding: String.Encoding.ascii.rawValue)! as String
        return UnsafePointer<Int8>(str)
    }
}
 
