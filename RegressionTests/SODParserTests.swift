import Foundation

// Run using: bash RegressionTests/run-sod-parser.sh
@main
struct SODParserRegressionTests {
    static func tlv(_ tag: UInt8, _ body: Data) -> Data {
        var length = body.count
        var encoded: [UInt8] = []
        repeat {
            encoded.insert(UInt8(length & 255), at: 0)
            length >>= 8
        } while length != 0
        let header = body.count < 128 ? [UInt8(body.count)] : [0x80 | UInt8(encoded.count)] + encoded
        return Data([tag] + header) + body
    }

    static func sequence(_ fields: [Data]) -> Data { tlv(0x30, fields.reduce(Data(), +)) }
    static func integer(_ value: UInt8) -> Data { tlv(2, Data([value])) }
    static let sha256 = Data([0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1])

    static func entry(_ id: UInt8, hash: Data = Data(repeating: 0x41, count: 32)) -> Data {
        sequence([integer(id), tlv(4, hash)])
    }

    static func object(_ entries: [Data], version: UInt8 = 0, extra: [Data] = [],
                       oid: Data = sha256, nullParameters: Bool = false) -> Data {
        let algorithm = sequence([tlv(6, oid)] + (nullParameters ? [tlv(5, Data())] : []))
        return sequence([integer(version), algorithm, sequence(entries)] + extra)
    }

    static func main() throws {
        var count = 0
        func accepted(_ data: Data, _ check: (String, [DataGroupId: String]) -> Bool) throws {
            let (algorithm, hashes) = try LDSSecurityObjectParser.parse(data)
            precondition(check(algorithm, hashes))
            count += 1
        }
        func rejected(_ data: Data) throws {
            do {
                _ = try LDSSecurityObjectParser.parse(data)
                fatalError("Malformed LDS object was accepted")
            } catch PassiveAuthenticationError.UnableToParseSODHashes {
                count += 1
            }
        }

        let info = sequence([tlv(0x13, Data("0108".utf8)), tlv(0x13, Data("040000".utf8))])
        let binary = Data([13, 10, 0, 32]) + Data(repeating: 0xff, count: 28)
        try accepted(object([entry(1), entry(2, hash: binary)])) {
            $0 == "SHA256" && $1[.DG1] == String(repeating: "41", count: 32)
                && $1[.DG2] == "0D0A0020" + String(repeating: "FF", count: 28)
        }
        try accepted(object([entry(1), entry(15)], version: 1, extra: [info])) { $1.count == 2 }
        let descriptiveInfo = sequence([tlv(0x13, Data("1.8".utf8)), tlv(0x13, Data("Unicode 4".utf8))])
        try accepted(object([entry(1), entry(2)], version: 1, extra: [descriptiveInfo])) { $1.count == 2 }
        let (_, rawHashes) = try LDSSecurityObjectParser.parseHashes(object([entry(1), entry(2, hash: binary)]))
        precondition(rawHashes[.DG2] == binary)
        count += 1
        try accepted(object([entry(1), entry(16)], nullParameters: true)) { $1[.DG16] != nil }
        try accepted(object((1...16).map { entry(UInt8($0)) })) { $1.count == 16 }

        let algorithms: [(Data, String, Int)] = [
            (Data([0x2b, 0x0e, 3, 2, 0x1a]), "SHA1", 20),
            (Data([0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 4]), "SHA224", 28),
            (Data([0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2]), "SHA384", 48),
            (Data([0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 3]), "SHA512", 64)
        ]
        for (oid, name, length) in algorithms {
            let hash = Data(repeating: 0, count: length)
            try accepted(object([entry(1, hash: hash), entry(2, hash: hash)], oid: oid)) {
                $0 == name && $1[.DG1]?.count == length * 2
            }
        }
        for id: UInt8 in [0, 17, 18, 255] { try rejected(object([entry(1), entry(id)])) }
        try rejected(object([entry(1), entry(1)]))
        try rejected(object([]))
        try rejected(object([entry(1)]))
        try rejected(object([entry(1), sequence([integer(2)])]))
        try rejected(object([entry(1), entry(2, hash: Data([1]))]))
        try rejected(object([entry(1), entry(2), tlv(4, binary)]))
        try rejected(object([entry(1), sequence([integer(2), tlv(4, binary), tlv(4, binary)])]))
        try rejected(object([entry(1), entry(2)], oid: Data([42, 3])))
        try rejected(object([entry(1), entry(2)], version: 1))
        try rejected(object([entry(1), entry(2)], extra: [info]))
        try rejected(object([entry(1), entry(2)], version: 1, extra: [tlv(4, binary)]))
        let valid = object([entry(1), entry(2)])
        try rejected(valid + Data([0]))
        try rejected(Data(valid.dropLast()))
        try rejected(Data([0x30, 0x80, 0, 0]))
        try rejected(Data([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]))
        print("PASS: \(count) structural SOD parser regression cases")
    }
}
