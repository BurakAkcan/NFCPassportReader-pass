import Foundation
import OpenSSL

/// Parses the encapsulated LDS Security Object, not the outer CMS container.
@available(iOS 13, macOS 10.15, *)
enum LDSSecurityObjectParser {
    private struct Element {
        let tag: Int32
        let constructed: Bool
        let body: Data

        func sequence() throws -> [Element] {
            guard tag == V_ASN1_SEQUENCE, constructed else {
                throw failure("Expected SEQUENCE")
            }
            return try elements(body)
        }

        func primitive(_ expectedTag: Int32) throws -> Data {
            guard tag == expectedTag, !constructed else {
                throw failure("Unexpected ASN.1 field")
            }
            return body
        }
    }

    static func parse(_ data: Data) throws -> (String, [DataGroupId: String]) {
        let (algorithm, hashes) = try parseHashes(data)
        return (algorithm, hashes.mapValues { hash in
            hash.map { String(format: "%02X", $0) }.joined()
        })
    }

    static func parseHashes(_ data: Data) throws -> (String, [DataGroupId: Data]) {
        let roots = try elements(data)
        guard roots.count == 1 else { throw failure("Expected one LDS Security Object") }
        let fields = try roots[0].sequence()
        guard fields.count == 3 || fields.count == 4 else {
            throw failure("Invalid LDS Security Object fields")
        }
        let version = try fields[0].primitive(V_ASN1_INTEGER)
        guard version == Data([0]) || version == Data([1]) else {
            throw failure("Unsupported LDS Security Object version")
        }
        guard fields.count == (version == Data([0]) ? 3 : 4) else {
            throw failure("LDS version information does not match version")
        }
        if fields.count == 4 {
            let info = try fields[3].sequence()
            guard info.count == 2 else { throw failure("Invalid LDS version information") }
            // Version metadata is not used to decide whether DG hashes match.
            for field in info {
                _ = try field.primitive(V_ASN1_PRINTABLESTRING)
            }
        }

        let algorithmFields = try fields[1].sequence()
        guard (1...2).contains(algorithmFields.count) else {
            throw failure("Invalid digest algorithm identifier")
        }
        let oid = try algorithmFields[0].primitive(V_ASN1_OBJECT)
        if algorithmFields.count == 2 {
            guard try algorithmFields[1].primitive(V_ASN1_NULL).isEmpty else {
                throw failure("Invalid digest algorithm parameters")
            }
        }
        let algorithms: [(Data, String, Int)] = [
            (Data([0x2b, 0x0e, 0x03, 0x02, 0x1a]), "SHA1", 20),
            (Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04]), "SHA224", 28),
            (Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]), "SHA256", 32),
            (Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]), "SHA384", 48),
            (Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]), "SHA512", 64)
        ]
        guard let (_, algorithm, hashLength) = algorithms.first(where: { $0.0 == oid }) else {
            throw failure("Unsupported digest algorithm")
        }
        let entries = try fields[2].sequence()
        guard (2...16).contains(entries.count) else { throw failure("Invalid data group count") }
        var hashes: [DataGroupId: Data] = [:]
        for entry in entries {
            let pair = try entry.sequence()
            guard pair.count == 2 else { throw failure("Invalid data group hash entry") }
            let number = try pair[0].primitive(V_ASN1_INTEGER)
            guard number.count == 1, let id = number.first, (1...16).contains(id) else {
                throw failure("Invalid data group number")
            }
            let group = DataGroupId.getIDFromName(name: "DG\(id)")
            guard hashes[group] == nil else { throw failure("Duplicate data group number") }
            let hash = try pair[1].primitive(V_ASN1_OCTET_STRING)
            guard hash.count == hashLength else { throw failure("Invalid data group hash length") }
            hashes[group] = hash
        }
        return (algorithm, hashes)
    }

    private static func failure(_ reason: String) -> PassiveAuthenticationError {
        .UnableToParseSODHashes(reason)
    }

    private static func elements(_ data: Data) throws -> [Element] {
        try data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return []
            }
            var offset = 0
            var result: [Element] = []
            while offset < buffer.count {
                var cursor: UnsafePointer<UInt8>? = base.advanced(by: offset)
                var length = 0
                var tag: Int32 = 0
                var tagClass: Int32 = 0
                let flags = ASN1_get_object(&cursor, &length, &tag, &tagClass, buffer.count - offset)
                // The signed LDS object uses definite-length encoding. Bound every read to its parent.
                guard flags & 0x80 == 0, flags & 1 == 0, tagClass == V_ASN1_UNIVERSAL,
                      let content = cursor, length >= 0 else {
                    throw failure("Invalid ASN.1 header")
                }
                let start = base.distance(to: content)
                guard start > offset, start <= buffer.count, length <= buffer.count - start else {
                    throw failure("Truncated ASN.1 value")
                }
                result.append(Element(tag: tag, constructed: flags & V_ASN1_CONSTRUCTED != 0,
                                      body: Data(bytes: content, count: length)))
                offset = start + length
            }
            return result
        }
    }
}
