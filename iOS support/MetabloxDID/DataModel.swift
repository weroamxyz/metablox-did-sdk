//
//  DataModel.swift
//  MetabloxDID
//
//  Created by TORA on 2022-05-26.
//

import Foundation
import MetabloxDID.DID
import CoreAudio

public struct DIDDocumentModel: Codable {
    
    public init(context: [String], id: String, createdDate: String, updatedDate: String, version: Float, vertificationMethod: [VerificationMethodModel], authentication: String) {
        self.context = context
        self.id = id
        self.created = createdDate
        self.updated = updatedDate
        self.version = version
        self.verificationMethod = vertificationMethod
        self.authentication = authentication
    }
    
    public var context: [String]
    public var id: String
    public var created: String
    public var updated: String
    public var version: Float
    public var verificationMethod: [VerificationMethodModel]
    public var authentication: String
    
    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case id
        case created
        case updated
        case version
        case verificationMethod
        case authentication
    }
}

public struct VerificationMethodModel: Codable {
    
    public init(id: String, type: String, controller: String, publicKeyMultiplebase: String) {
        self.id = id
        self.type = type
        self.controller = controller
        self.publicKeyMultibase = publicKeyMultiplebase
    }
    
    public var id: String
    public var type: String
    public var controller: String
    public var publicKeyMultibase: String
}

public struct VCCoreModel : Codable {
    public init(context: [String], id: String, type: [String], subType: String, issuer: String, issuanceDate: String, expirationDate: String, description: String, credentialSubject: [String], vcProof: CoreProofModel, revoked: Bool) {
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
    public var vcProof: CoreProofModel
    public var revoked: Bool
}

extension VCCoreModel {
    public init(vc: UnsafeMutablePointer<VC>) {
        context = toArray(ptr: vc.pointee.context, length: Int(vc.pointee.count_context))
        id = withUnsafePointer(to: &vc.pointee.id.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        type = toArray(ptr: vc.pointee.type, length: Int(vc.pointee.count_type))
        subType = withUnsafePointer(to: &vc.pointee.sub_type.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        issuer = withUnsafePointer(to: &vc.pointee.issuer.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        issuanceDate = withUnsafePointer(to: &vc.pointee.issuance_data.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        expirationDate = withUnsafePointer(to: &vc.pointee.expiration_data.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        description = withUnsafePointer(to: &vc.pointee.description.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        credentialSubject = toArray(ptr: vc.pointee.CredentialSubject, length: Int(vc.pointee.count_subject))
        vcProof = CoreProofModel(vcProof: &vc.pointee.vcProof)
        revoked = (vc.pointee.revoked != 0)
    }
    
    public func toCStruct() -> UnsafeMutablePointer<VC>? {
        let contextptr = UnsafePointer(toDoublePtr(strArr: context))
        let typeptr = UnsafePointer(toDoublePtr(strArr: type))
        let credentialSubjectPtr =  UnsafePointer(toDoublePtr(strArr: credentialSubject))
        let vc = new_vc(contextptr, Int32(context.count), id, typeptr, Int32(type.count), subType, issuer, issuanceDate, expirationDate, description, credentialSubjectPtr, Int32(credentialSubject.count), vcProof.toVCProof(), revoked ? 1 : 0)
        return vc
    }
}

public struct VPCoreModel: Codable{
    public init(context: [String], type: [String], vc: [VCCoreModel], holder: String, vpProof: CoreProofModel) {
        self.context = context
        self.type = type
        self.vc = vc
        self.holder = holder
        self.vpProof = vpProof
    }
    
    public var context: [String]
    public var type: [String]
    public var vc: [VCCoreModel]
    public var holder: String
    public var vpProof: CoreProofModel
}

extension VPCoreModel {
    public init(vp: UnsafeMutablePointer<VP>) {
        context = toArray(ptr: vp.pointee.context, length: Int(vp.pointee.count_context))
        type = toArray(ptr: vp.pointee.type, length: Int(vp.pointee.count_type))
        
        holder = withUnsafePointer(to: &vp.pointee.holder.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }

        vc = []
        let vcCount = Int(vp.pointee.count_vc)
        for i in 0..<vcCount {
            let vcPtr = vp.pointee.vc[i]
            let c = VCCoreModel(vc: vcPtr!)
            vc.append(c)
        }
        vpProof = CoreProofModel(vpProof: &vp.pointee.vpProof)
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

let pubkeyLength = 65
public struct CoreProofModel : Codable {
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
        type = withUnsafePointer(to: &vcProof.pointee.type.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        created = withUnsafePointer(to: &vcProof.pointee.created.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        verificationMethod = withUnsafePointer(to: &vcProof.pointee.verification_method.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        proofPurpose = withUnsafePointer(to: &vcProof.pointee.proof_purpose.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }

        publicKey = Data(bytes: &vcProof.pointee.public_key.0, count: pubkeyLength).base64EncodedString()
        JWSSignature = withUnsafePointer(to: &vcProof.pointee.JWSSignature.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        nonce = nil
    }
    
    public init(vpProof: UnsafeMutablePointer<VPProof>) {
        type = withUnsafePointer(to: &vpProof.pointee.type.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }

        created = withUnsafePointer(to: &vpProof.pointee.created.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }

        verificationMethod = withUnsafePointer(to: &vpProof.pointee.verification_method.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }

        proofPurpose = withUnsafePointer(to: &vpProof.pointee.proof_purpose.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }

        publicKey = Data(bytes: &vpProof.pointee.public_key.0, count: pubkeyLength).base64EncodedString()

        JWSSignature = withUnsafePointer(to: &vpProof.pointee.JWSSignature.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }

        nonce = withUnsafePointer(to: &vpProof.pointee.nonce.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
    }
    
    public func toVCProof()-> UnsafeMutablePointer<VCProof>? {
        let pubkey = Data(base64Encoded: publicKey)?.toBytesCopy()
        defer {
            pubkey?.deallocate()
        }
        let p = new_vc_proof(type, created, verificationMethod, proofPurpose, JWSSignature, pubkey)
        return p
    }

    public func toVPProof()-> UnsafeMutablePointer<VPProof>? {
        let pubkey = Data(base64Encoded: publicKey)?.toBytesCopy()
        defer {
            pubkey?.deallocate()
        }
        let p = new_vp_proof(type, created, verificationMethod, proofPurpose, JWSSignature, nonce ?? "", pubkey)
        return p
    }
}


public struct QOSCoreModel: Codable {
    
    public init(bandwidth: String, rssi: String, packetLose: String, nonce: String, jws: String) {
        self.bandwidth = bandwidth
        self.rssi = rssi
        self.packetLose = packetLose
        self.nonce = nonce
        self.jwsSignature = jws
    }
    
    public var nonce: String
    public var bandwidth: String
    public var rssi: String
    public var packetLose: String
    public var jwsSignature: String
}

extension QOSCoreModel {
    public init(qos: UnsafeMutablePointer<QOS>) {
        nonce = withUnsafePointer(to: &qos.pointee.nonce.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        bandwidth = withUnsafePointer(to: &qos.pointee.bandwidth.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        rssi = withUnsafePointer(to: &qos.pointee.rssi.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        packetLose = withUnsafePointer(to: &qos.pointee.packLose.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
        jwsSignature = withUnsafePointer(to: &qos.pointee.JWSSignature.0) {
            $0.withMemoryRebound(to: UInt8.self, capacity: MemoryLayout.size(ofValue: $0)) { pointer in
                String(cString: pointer)
            }
        }
    }
    
    public func toCStruct() -> UnsafeMutablePointer<QOS>? {
        let qos = new_qos(nonce, bandwidth, rssi, packetLose, jwsSignature)
        return qos
    }
}
