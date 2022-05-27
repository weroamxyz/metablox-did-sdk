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
        wallet_handle_destroy(walletHandlerPtr)
        did_destroy(loadedDIDPtr)
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
    
    // Read did string from loaded didptr
    public func readDIDString(withSchemaPrefix: Bool = false)-> String? {
        guard let did = self.loadedDIDPtr,
              let meta = did_to_did_meta(did),
              let DIDStr = String(cString: &meta.pointee.did.0, encoding: .utf8)
        else {
            return nil
        }
        return withSchemaPrefix ? "did:metablox:" + DIDStr : DIDStr
    }
    
    private let pubkeyLength = 45
    // Read publickey string from loaded didptr, in the format of address
    public func readDIDPublicKey()-> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: pubkeyLength)
        buffer.initialize(repeating: 0, count: pubkeyLength)
        did_export_pubkey(did, buffer)
        let pubkeyStr = String(cString: buffer, encoding: .utf8)
        defer {
            buffer.deallocate()
        }
        return pubkeyStr
    }
    
    // Read publckey string from loaded didptr, in the format of base64 string of raw bytes
    public func readRawPublickeyInBase64() -> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        
        let bufferLength = 65
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: bufferLength)
        buffer.initialize(repeating: 0, count: bufferLength)
        did_get_pubkey(did, buffer, bufferLength)
        let pubkeyStr = Data(bytes: buffer, count: bufferLength).base64EncodedString()
        defer {
            buffer.deallocate()
        }
        return pubkeyStr
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
    public func signature(contentHash: Data)-> (sig: Data, r: Data, s: Data, v: UInt8)? {
        guard let did = self.loadedDIDPtr else {return nil}
        
        let bytes = [UInt8](contentHash)
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: DIDSignatureLength)
        buffer.initialize(repeating: 0, count: DIDSignatureLength)
        did_sign_hash(did, bytes, buffer, DIDSignatureLength)
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
    public func verifySignature(contentHash: Data, signature: Data) -> Bool {
        let contentUChars = [UInt8](contentHash)
        guard let did = self.loadedDIDPtr else {
            return false
        }
        
        let didMeta = did_to_did_meta(did)
        let bytes = signature.toBytesCopy()
        defer {
            bytes.deallocate()
        }
        let result = did_verify_hash(didMeta?.pointee.did_keys, contentUChars,  bytes, DIDSignatureLength)
        return result == 0
    }
    
    private let DIDPrivateKeyLength = 128
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
        let names = nameListStruct.pointee.names
        let nameList = toArray(ptr: names, length: listLength)
        
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
    
    // Verify the content and signature of a VC
    public func verifyVC(_ vc: VCCoreModel) -> Bool {
        let vc_c = vc.toCStruct()
        let r = vc_verify(vc_c)
        defer {
            vc_destroy(vc_c)
        }
        return r == 0
    }
    
    // Verify the content and signatures of a VP
    public func verifyVP(_ vp: VPCoreModel) -> Bool {
        let vp_c = vp.toCStruct()
        let r = vp_verify(vp_c)
        defer {
            vp_destroy(vp_c)
        }
        return r == 0
    }
    
    // Generate and sign a VP with a VC
    public func generateVPAndSign(vc: VCCoreModel) -> VPCoreModel? {
        guard let didPtr = self.loadedDIDPtr,
              let didStr = self.readDIDString(withSchemaPrefix: true),
              let pubkey = self.readRawPublickeyInBase64()
        else {
            return nil
        }
        
        let createdTime: String
        if #available(iOS 15.0, *) {
            createdTime = Date.now.ISO8601Format()
        } else {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
            createdTime = formatter.string(from: Date())
        }
        let nonce = String(Date().timeIntervalSince1970)
        let vpProof = ProofModel(type: "EcdsaSecp256k1Signature2019",
                                 created: createdTime,
                                 verificationMethod: didStr + "#verification",
                                 proofPurpose: "Authentication",
                                 publicKey: pubkey,
                                 JWSSignature: "",
                                 nonce: nonce)
        let context = ["https://www.w3.org/2018/credentials/v1",
                       "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#"]
        let type = ["VerifiablePresentation"]
        let vp = VPCoreModel(context: context, type: type, vc: [vc], holder: didStr, vpProof: vpProof)
        guard let vp_c = vp.toCStruct() else { return nil }
        
        vp_signature(vp_c, didPtr, &vp_c.pointee.vpProof.JWSSignature.0)
        
        let vp2 = VPCoreModel(vp: vp_c)
        defer {
            vp_destroy(vp_c)
        }
        
        return vp2
    }
}


