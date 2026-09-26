#!/usr/bin/env python3

import pathlib
import sys


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} match count is {count}, expected 1")
    return text.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: patch_ldid_core_entitlements.py input output")

    source = pathlib.Path(sys.argv[1])
    destination = pathlib.Path(sys.argv[2])
    text = source.read_text()

    text = replace_once(
        text,
        "#include <openssl/pkcs12.h>\n#include <openssl/ui.h>",
        "#include <openssl/pkcs12.h>\n"
        "#include <CoreFoundation/CoreFoundation.h>\n"
        "#include <openssl/ui.h>",
        "CoreFoundation include",
    )

    anchor = """static inline uint16_t Swap_(uint16_t value) {
"""
    serializer = """extern \"C\" const void *CESerializeCFDictionary(
    CFAllocatorRef allocator, CFDictionaryRef dictionary,
    CFDataRef *serialized);

static std::string core_entitlements_der(plist_t data) {
    char *xml(NULL);
    uint32_t xml_size(0);
    plist_to_xml(data, &xml, &xml_size);
    _scope({ free(xml); });
    if (xml == NULL || xml_size == 0)
        return std::string();

    CFDataRef xml_data = CFDataCreate(
        kCFAllocatorDefault, reinterpret_cast<const UInt8 *>(xml), xml_size);
    if (xml_data == NULL)
        return std::string();
    CFErrorRef property_error = NULL;
    CFPropertyListRef property = CFPropertyListCreateWithData(
        kCFAllocatorDefault, xml_data, kCFPropertyListImmutable, NULL,
        &property_error);
    CFRelease(xml_data);
    if (property_error != NULL)
        CFRelease(property_error);
    if (property == NULL ||
        CFGetTypeID(property) != CFDictionaryGetTypeID()) {
        if (property != NULL)
            CFRelease(property);
        return std::string();
    }

    CFDataRef serialized = NULL;
    (void)CESerializeCFDictionary(kCFAllocatorDefault,
                                  (CFDictionaryRef)property, &serialized);
    CFRelease(property);
    if (serialized == NULL)
        return std::string();
    std::string result(
        reinterpret_cast<const char *>(CFDataGetBytePtr(serialized)),
        (size_t)CFDataGetLength(serialized));
    CFRelease(serialized);
    return result;
}

static inline uint16_t Swap_(uint16_t value) {
"""
    text = replace_once(text, anchor, serializer, "serializer insertion")

    text = replace_once(
        text,
        "            baton.derformat_ = der(combined);\n",
        "            baton.derformat_ = core_entitlements_der(combined);\n"
        "            if (baton.derformat_.empty()) {\n"
        "                fprintf(stderr,\n"
        "                        \"ldid: CoreEntitlements DER serialization failed\\n\");\n"
        "                exit(1);\n"
        "            }\n",
        "DER serializer call",
    )

    text = replace_once(
        text,
        """        req(requirement, exprForm);
        req(requirement, opAnd);
        req(requirement, opIdent);
        req(requirement, identifier);
        req(requirement, opAnd);
        req(requirement, opAppleGenericAnchor);
        req(requirement, opAnd);
        req(requirement, opCertField);
        req(requirement, 0);
        req(requirement, "subject.CN");
        req(requirement, matchEqual);
        req(requirement, common);
        req(requirement, opCertGeneric);
        req(requirement, 1);
        req(requirement, (uint8_t []) {APPLE_EXTENSION_OID, 2, 1});
        req(requirement, matchExists);
""",
        """        req(requirement, exprForm);
        if (signer) {
            req(requirement, opAnd);
            req(requirement, opIdent);
            req(requirement, identifier);
            req(requirement, opAnd);
            req(requirement, opAppleGenericAnchor);
            req(requirement, opAnd);
            req(requirement, opCertField);
            req(requirement, 0);
            req(requirement, "subject.CN");
            req(requirement, matchEqual);
            req(requirement, common);
            req(requirement, opCertGeneric);
            req(requirement, 1);
            req(requirement, (uint8_t []) {APPLE_EXTENSION_OID, 2, 1});
            req(requirement, matchExists);
        } else {
            req(requirement, opIdent);
            req(requirement, identifier);
        }
""",
        "ad-hoc designated requirement",
    )

    destination.write_text(text)


if __name__ == "__main__":
    main()
