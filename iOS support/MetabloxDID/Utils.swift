//
//  Utils.swift
//  MetabloxDID
//
//  Created by TORA on 2022-05-26.
//

import Foundation
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
