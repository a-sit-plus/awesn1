// Generates a BoringSSL-derived T61String decoding corpus as JSON.
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

static std::string Hex(const std::vector<uint8_t> &in) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(in.size() * 2);
  for (uint8_t b : in) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 15]);
  }
  return out;
}

static std::string JsonString(const uint8_t *in, size_t len) {
  std::string out = "\"";
  for (size_t i = 0; i < len; i++) {
    const uint8_t b = in[i];
    switch (b) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (b < 0x20) {
          char escaped[7];
          std::snprintf(escaped, sizeof(escaped), "\\u%04x", b);
          out += escaped;
        } else {
          out.push_back(static_cast<char>(b));
        }
    }
  }
  out += '"';
  return out;
}

static std::vector<uint8_t> Der(const std::vector<uint8_t> &content) {
  std::vector<uint8_t> out = {0x14};
  if (content.size() < 128) {
    out.push_back(static_cast<uint8_t>(content.size()));
  } else {
    out.push_back(0x82);
    out.push_back(static_cast<uint8_t>(content.size() >> 8));
    out.push_back(static_cast<uint8_t>(content.size()));
  }
  out.insert(out.end(), content.begin(), content.end());
  return out;
}

static void Emit(const std::vector<uint8_t> &der, bool first) {
  const uint8_t *cursor = der.data();
  ASN1_T61STRING *value = d2i_ASN1_T61STRING(nullptr, &cursor, der.size());
  uint8_t *utf8 = nullptr;
  int utf8_len = -1;
  if (value != nullptr && cursor == der.data() + der.size()) {
    utf8_len = ASN1_STRING_to_UTF8(&utf8, value);
  }
  const bool valid = utf8_len >= 0;
  std::printf("%s    {\"der\":\"%s\",\"shouldParse\":%s,\"expectedUtf8\":",
              first ? "" : ",\n", Hex(der).c_str(), valid ? "true" : "false");
  if (valid) {
    const std::string json = JsonString(utf8, static_cast<size_t>(utf8_len));
    std::fputs(json.c_str(), stdout);
  } else {
    std::fputs("null", stdout);
    ERR_clear_error();
  }
  std::fputs("}", stdout);
  OPENSSL_free(utf8);
  ASN1_T61STRING_free(value);
}

int main() {
  std::vector<std::vector<uint8_t>> vectors;
  vectors.push_back(Der({}));
  for (unsigned value = 0; value <= 0xff; value++) {
    vectors.push_back(Der({static_cast<uint8_t>(value)}));
  }
  vectors.push_back(Der({'h', 'e', 'l', 'l', 'o'}));
  vectors.push_back(Der({'M', 0xfc, 'l', 'l', 'e', 'r'}));
  std::vector<uint8_t> all_octets(256);
  for (unsigned value = 0; value <= 0xff; value++) all_octets[value] = value;
  vectors.push_back(Der(all_octets));

  // Malformed envelopes and non-T61 input. BoringSSL decides the oracle result.
  vectors.push_back({});
  vectors.push_back({0x14});
  vectors.push_back({0x14, 0x01});
  vectors.push_back({0x14, 0x02, 'a'});
  vectors.push_back({0x0c, 0x01, 'a'});
  vectors.push_back({0x14, 0x80, 0x00, 0x00});
  vectors.push_back({0x14, 0x01, 'a', 0x00});

  std::puts("{\n  \"source\":\"BoringSSL c63fadbde60a2224c22189d14c4001bbd2a3a629\",\n  \"vectors\":[");
  for (size_t i = 0; i < vectors.size(); i++) Emit(vectors[i], i == 0);
  std::puts("\n  ]\n}");
  return 0;
}
