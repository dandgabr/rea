/** Critical interchange/config/locality/mutation sources at the audited official pins.
 * Imported dependencies and the complete installation remain separately trusted;
 * these hashes are not an attestation of all interpreter/site-package code.
 */
export const FACT_NATIVE_SOURCE_PINS = {
  "release-4.4.1": {
    "firmware_import_export.py":
      "0dec15c653fa28d36d77bd437fa5aca3c8fa152e61a6eb6b9672d4a4d905190f",
    "config.py":
      "d90953d47801e108cbe0c93ca846af525add68e004b50c3c3f81c5577b3ee2bb",
    "storage/db_connection.py":
      "27203cd2edcf841a526d943f0ab2d3891be3e492a233018ef62c4c299277ee1f",
    "storage/db_interface_backend.py":
      "2337b399ae44e7f890314b2f8e0180268e3f1a101bfdfb85fe40eaeb2fc96260",
    "storage/db_interface_base.py":
      "0f531918a63425bda32d81528b903f0b27431dd6a966af25242279cff52b9fd1",
    "storage/migration/__init__.py":
      "8b34e92356f80ce0c3a008060677f448d568d0f48281600a8fad6409274768a3",
    "objects/file.py":
      "1195fdf8c8ddaec1e552239c78473e351f23e94ef3af6063717ee23c0c6002c5",
    "objects/firmware.py":
      "35ebf0e5ba7754427460a0016dfcd7e5869636e0f702736b3e283ecf6ea5389a",
    "helperFunctions/database.py":
      "6027754b7fec82f9507808b0a55e5cd626e3bf8dbcbc103d40d31e8036342f88",
    "storage/entry_conversion.py":
      "56e0905987de984462eb13760711f2e723e1d552eea95921307bace86e2ead4d",
    "storage/schema.py":
      "4096208ad44b40b03fbe1ab375d55da03a147f9f9533b29cfa25c5acd4a66f4e",
    "storage/fsorganizer.py":
      "cced898d9f335d8286f88229c820c4e4ffc1adfca0c5dd201d1437488f5f2da1",
  },
  "source-54aed90b": {
    "firmware_import_export.py":
      "2e8a1ee01157dd90cd2c63771d6e7ad25f8d96732a4aaaae376aca7e6a507cdf",
    "config.py":
      "d90953d47801e108cbe0c93ca846af525add68e004b50c3c3f81c5577b3ee2bb",
    "storage/db_connection.py":
      "27203cd2edcf841a526d943f0ab2d3891be3e492a233018ef62c4c299277ee1f",
    "storage/db_interface_backend.py":
      "2337b399ae44e7f890314b2f8e0180268e3f1a101bfdfb85fe40eaeb2fc96260",
    "storage/db_interface_base.py":
      "f119b275dc6f129c028740fe6abf61986cb74c993de94ab6a917f8852a29eaf4",
    "storage/migration/__init__.py":
      "8b34e92356f80ce0c3a008060677f448d568d0f48281600a8fad6409274768a3",
    "objects/file.py":
      "2e815b24018c293e0cf0eb3341c94dfc5bc46b7d5efa688860a6349bf4aae78b",
    "objects/firmware.py":
      "38a8cee129594673ffcd648de7a1a0f2d518be2c5165200843640a9512316841",
    "helperFunctions/database.py":
      "6027754b7fec82f9507808b0a55e5cd626e3bf8dbcbc103d40d31e8036342f88",
    "storage/entry_conversion.py":
      "66057555d035ef3e15e55e4e2b1f08140633f49a27729b6898276b3243e00816",
    "storage/schema.py":
      "4096208ad44b40b03fbe1ab375d55da03a147f9f9533b29cfa25c5acd4a66f4e",
    "storage/file_service.py":
      "16e6066d99d19d25f51d369bc6f9be3e0de732ba30544178ac079f282174252b",
  },
} as const;
