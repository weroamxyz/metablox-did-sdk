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
    
    public func readDIDString()-> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        guard let meta = did_to_did_meta(did) else {return nil}
        let DIDStr = String(cString: &meta.pointee.did.0, encoding: .utf8)
        return DIDStr
    }
    
    private let pubkeyLength = 45
    public func readDIDPublicKey()-> String? {
        guard let did = self.loadedDIDPtr else {return nil}
        
        let buffer: UnsafeMutablePointer<CChar> = .allocate(capacity: pubkeyLength)
        buffer.initialize(repeating: 0, count: pubkeyLength)
        did_export_pubkey(did, buffer)
        let pubkeyStr = String(cString: buffer, encoding: .utf8)
        defer {
            buffer.deinitialize(count: pubkeyLength)
        }
        return pubkeyStr
        
//        guard let meta = did_to_did_meta(did) else {return nil}
//        let pubkey = String(validatingUTF8: &(meta.pointee.did_keys.pointee.publicKeyHex.0))
//        return pubkey
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
    public func verifySignature(contentHash: Data, signature: Data, finishHandler:(Int)->()) {
        let contentUChars = [UInt8](contentHash)
        guard let did = self.loadedDIDPtr else {
            finishHandler(-1)
            return
        }
        
        var sign = signature
        let didMeta = did_to_did_meta(did)
        sign.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<CChar>) in
            let result = did_verify_hash(didMeta?.pointee.did_keys, contentUChars,  bytes, DIDSignatureLength)
            finishHandler(Int(result))
        }
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
}

public struct VCModel {
    public init(context: [String], id: String, type: [String], subType: String, issuer: String, issuanceDate: String, expirationDate: String, description: String, credentialSubject: [String], vcProof: ProofModel, revoked: Bool) {
        self.context = context
        self.id = id
        self.type = type
        self.subType = subType
        self.issuer = issuer
        self.issuanceDate = issuanceDate
        self.expirationDate = expirationDate
        self.description = description
        self.credentialSubject = credentialSubject
        self.vcProof = vcProof
        self.revoked = revoked
    }
    
    public var context: [String]
    public var id: String
    public var type: [String]
    public var subType: String
    public var issuer: String
    public var issuanceDate: String
    public var expirationDate: String
    public var description: String
    public var credentialSubject: [String]
    public var vcProof: ProofModel
    public var revoked: Bool
}

extension VCModel {
    public init(vc: UnsafeMutablePointer<VC>) {
        context = toArray(ptr: vc.pointee.context, length: Int(vc.pointee.count_context))
        id = String(cString: &vc.pointee.id.0, encoding: .utf8) ?? ""
        type = toArray(ptr: vc.pointee.type, length: Int(vc.pointee.count_type))
        subType = String(cString: &vc.pointee.sub_type.0, encoding: .utf8) ?? ""
        issuer = String(cString: &vc.pointee.issuer.0, encoding: .utf8) ?? ""
        issuanceDate = String(cString: &vc.pointee.issuance_data.0, encoding: .utf8) ?? ""
        expirationDate = String(cString: &vc.pointee.expiration_data.0, encoding: .utf8) ?? ""
        description = String(cString: &vc.pointee.description.0, encoding: .utf8) ?? ""
        credentialSubject = toArray(ptr: vc.pointee.CredentialSubject, length: Int(vc.pointee.count_subject))
        vcProof = ProofModel(vcProof: &vc.pointee.vcProof)
        revoked = (vc.pointee.revoked != 0)
    }
    
    public func toCStruct() -> UnsafeMutablePointer<VC>? {
        let contextptr = UnsafePointer(toDoublePtr(strArr: context))
        let typeptr = UnsafePointer(toDoublePtr(strArr: type))
        let credentialSubjectPtr =  UnsafePointer(toDoublePtr(strArr: credentialSubject))
        let vc = new_vc(contextptr, Int32(context.count), id, typeptr, Int32(type.count), subType, issuer, issuanceDate, expirationDate, description, credentialSubjectPtr, Int32(credentialSubject.count), vcProof.toVCProof()!.pointee, revoked ? 1 : 0)
        return vc
    }
}

public struct VPModel {
    public init(context: [String], type: [String], vc: [VCModel], holder: String, vpProof: ProofModel) {
        self.context = context
        self.type = type
        self.vc = vc
        self.holder = holder
        self.vpProof = vpProof
    }
    
    public var context: [String]
    public var type: [String]
    public var vc: [VCModel]
    public var holder: String
    public var vpProof: ProofModel
}

extension VPModel {
    public init(vp: UnsafeMutablePointer<VP>) {
        context = toArray(ptr: vp.pointee.context, length: Int(vp.pointee.count_context))
        type = toArray(ptr: vp.pointee.type, length: Int(vp.pointee.count_type))
        holder = String(cString: &vp.pointee.holder.0, encoding: .utf8) ?? ""
        vc = []
        let vcCount = Int(vp.pointee.count_vc)
        for i in 0..<vcCount {
            let vcPtr = vp.pointee.vc[i]
            let c = VCModel(vc: vcPtr!)
            vc.append(c)
        }
        vpProof = ProofModel(vpProof: &vp.pointee.vpProof)
    }
    
    public func toCStruct() -> UnsafeMutablePointer<VP>? {
        let contextptr = UnsafePointer(toDoublePtr(strArr: context))
        let typeptr = UnsafePointer(toDoublePtr(strArr: type))
        
        let vcPtr = UnsafeMutablePointer<UnsafeMutablePointer<VC>?>.allocate(capacity: vc.count)
        var vcArr = vc.map {
            $0.toCStruct()
        }
        vcArr.append(nil)
        vcPtr.initialize(from: vcArr, count: vc.count)
        
        let vp = new_vp(contextptr, Int32(context.count), typeptr, Int32(type.count), UnsafePointer(vcPtr), Int32(vc.count), holder, vpProof.toVPProof())
        
        return vp
    }
}

public struct ProofModel {
    public init(type: String, created: String, verificationMethod: String, proofPurpose: String, publicKey: String, JWSSignature: String, nonce: String? = nil) {
        self.type = type
        self.created = created
        self.verificationMethod = verificationMethod
        self.proofPurpose = proofPurpose
        self.publicKey = publicKey
        self.JWSSignature = JWSSignature
        self.nonce = nonce
    }
    
    public var type: String
    public var created: String
    public var verificationMethod: String
    public var proofPurpose: String
    public var publicKey: String
    public var JWSSignature: String
    public var nonce: String?
    
    public init(vcProof: UnsafeMutablePointer<VCProof>) {
        type = String(cString: &vcProof.pointee.type.0, encoding: .utf8) ?? ""
        created = String(cString: &vcProof.pointee.created.0, encoding: .utf8) ?? ""
        verificationMethod = String(cString: &vcProof.pointee.verification_method.0, encoding: .utf8) ?? ""
        proofPurpose = String(cString: &vcProof.pointee.proof_purpose.0, encoding: .utf8) ?? ""
        publicKey = String(cString: &vcProof.pointee.public_key.0, encoding: .utf8) ?? ""
        JWSSignature = String(cString: &vcProof.pointee.JWSSignature.0, encoding: .utf8) ?? ""
        nonce = nil
    }
    
    public init(vpProof: UnsafeMutablePointer<VPProof>) {
        type = String(cString: &vpProof.pointee.type.0, encoding: .utf8) ?? ""
        created = String(cString: &vpProof.pointee.created.0, encoding: .utf8) ?? ""
        verificationMethod = String(cString: &vpProof.pointee.verification_method.0, encoding: .utf8) ?? ""
        proofPurpose = String(cString: &vpProof.pointee.proof_purpose.0, encoding: .utf8) ?? ""
        publicKey = String(cString: &vpProof.pointee.public_key.0, encoding: .utf8) ?? ""
        JWSSignature = String(cString: &vpProof.pointee.JWSSignature.0, encoding: .utf8) ?? ""
        nonce = String(cString: &vpProof.pointee.nonce.0, encoding: .utf8)
    }
    
    public func toVCProof()-> UnsafeMutablePointer<VCProof>? {
        let p = new_vc_proof(type, created, verificationMethod, proofPurpose, JWSSignature, publicKey)
        return p
    }

    public func toVPProof()-> UnsafeMutablePointer<VPProof>? {
        let p = new_vp_proof(type, created, verificationMethod, proofPurpose, JWSSignature, nonce ?? "", publicKey)
        return p
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

func toArray(ptr: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, length: Int) -> [String] {
    var arr:[String] = []
    guard ptr != nil else {
        return arr
    }
    for i in 0..<length {
        if let cptr = ptr![i] {
            let str = String(cString: cptr, encoding: .utf8) ?? ""
            arr.append(str)
        } else {
            arr.append("")
        }
        
    }
    return arr
}

func toDoublePtr(strArr: [String]) -> UnsafeMutablePointer<UnsafeMutablePointer<CChar>?> {
    var cStrs = strArr.map { str in
        strdup(str)
    }
    cStrs.append(nil)
    
    let ptr = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: cStrs.count)
    ptr.initialize(from: &cStrs, count: cStrs.count)
    
    return ptr
}
