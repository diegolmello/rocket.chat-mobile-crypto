import { useState, useEffect } from 'react';
import { Text, View, StyleSheet, ScrollView, Button } from 'react-native';
import {
  shaBase64,
  shaUtf8,
  pbkdf2Hash,
  hmac256,
  aesEncrypt,
  aesDecrypt,
  randomUuid,
  randomKey,
  randomBytes,
  rsaGenerateKeys,
  rsaEncrypt,
  rsaDecrypt,
  rsaSign,
  rsaVerify,
  getRandomValues,
  rsaImportKey,
  rsaExportKey,
  type JWK,
} from '@rocket.chat/mobile-crypto';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

export default function App() {
  const [results, setResults] = useState<{ [key: string]: string }>({});
  const [loading, setLoading] = useState<{ [key: string]: boolean }>({});

  const runCryptoTests = async () => {
    const tests = [
      {
        key: 'utf8-sha256',
        label: 'SHA-256 UTF-8 ("hello")',
        fn: () => shaUtf8('hello', 'SHA-256'),
        expected:
          '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
      },
      {
        key: 'utf8-sha1',
        label: 'SHA-1 UTF-8 ("hello")',
        fn: () => shaUtf8('hello', 'SHA-1'),
        expected: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
      },
      {
        key: 'base64-sha256',
        label: 'SHA-256 Base64 ("aGVsbG8=")',
        fn: () => shaBase64('aGVsbG8=', 'SHA-256'), // "hello" in base64
        expected: 'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=',
      },
      {
        key: 'utf8-sha512',
        label: 'SHA-512 UTF-8 ("test")',
        fn: () => shaUtf8('test', 'SHA-512'),
        expected:
          'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff',
      },
      {
        key: 'pbkdf2-sha256',
        label: 'PBKDF2-SHA256 ("cGFzc3dvcmQ=", "c2FsdA==", 1000, 32)',
        fn: () => pbkdf2Hash('cGFzc3dvcmQ=', 'c2FsdA==', 1000, 32, 'SHA256'), // "password", "salt"
        expected: 'YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM=',
      },
      {
        key: 'pbkdf2-sha1',
        label: 'PBKDF2-SHA1 ("cGFzc3dvcmQ=", "c2FsdA==", 1000, 20)',
        fn: () => pbkdf2Hash('cGFzc3dvcmQ=', 'c2FsdA==', 1000, 20, 'SHA1'), // "password", "salt"
        expected: 'boi+i61+rp2eEKoGEiQDT+1I0D8=',
      },
      {
        key: 'pbkdf2-sha256-100k',
        label:
          'PBKDF2-SHA256 ("cGFzc3dvcmQ=", "c2FsdA==", 100000, 32) - High Iterations',
        fn: () => pbkdf2Hash('cGFzc3dvcmQ=', 'c2FsdA==', 100000, 32, 'SHA256'), // "password", "salt", 100k iterations
        expected: 'A5Si7eMyyaE+uC6bJGMWBMMd+Xi04vD70sVJlE+deaU=', // Expected value for 100k iterations
      },
      {
        key: 'hmac256-test1',
        label: 'HMAC-SHA256 (data="48656c6c6f", key="6b6579")', // "Hello", "key"
        fn: () => hmac256('48656c6c6f', '6b6579'),
        expected:
          'c70b9f4d665bd62974afc83582de810e72a41a58db82c538a9d734c9266d321e',
      },
      {
        key: 'hmac256-test2',
        label: 'HMAC-SHA256 (data="74657374", key="6b6579")', // "test", "key"
        fn: () => hmac256('74657374', '6b6579'),
        expected:
          '02afb56304902c656fcb737cdd03de6205bb6d401da2812efd9b2d36a08af159',
      },
      {
        key: 'aes-encrypt-test',
        label: 'AES Encrypt ("SGVsbG8gV29ybGQ=", key, iv)', // "Hello World" in base64
        fn: async () => {
          const encrypted = await aesEncrypt(
            'SGVsbG8gV29ybGQ=', // "Hello World" base64
            '0123456789abcdef0123456789abcdef', // 128-bit key in hex
            'fedcba9876543210fedcba9876543210' // 128-bit IV in hex
          );
          return encrypted || 'null';
        },
        expected: 'encrypted', // We'll verify it's not null and not the original
      },
      {
        key: 'aes-roundtrip-test',
        label: 'AES Encrypt->Decrypt Roundtrip',
        fn: async () => {
          const original = 'SGVsbG8gV29ybGQ='; // "Hello World" base64
          const key = '0123456789abcdef0123456789abcdef';
          const iv = 'fedcba9876543210fedcba9876543210';

          const encrypted = await aesEncrypt(original, key, iv);
          if (!encrypted) return 'encrypt failed';

          const decrypted = await aesDecrypt(encrypted, key, iv);
          return decrypted === original ? 'PASS' : `FAIL: got ${decrypted}`;
        },
        expected: 'PASS',
      },
      {
        key: 'random-uuid-test',
        label: 'Random UUID Generation',
        fn: async () => {
          const uuid = await randomUuid();
          // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
          const uuidRegex =
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
          return uuidRegex.test(uuid) ? 'VALID UUID' : `INVALID: ${uuid}`;
        },
        expected: 'VALID UUID',
      },
      {
        key: 'random-key-test',
        label: 'Random Key Generation (16 bytes)',
        fn: async () => {
          const key = await randomKey(16);
          // Should be 32 hex characters for 16 bytes
          const hexRegex = /^[0-9a-f]{32}$/i;
          return hexRegex.test(key)
            ? `VALID KEY (${key.length} chars)`
            : `INVALID: ${key}`;
        },
        expected: 'VALID KEY (32 chars)',
      },
      {
        key: 'random-bytes-test',
        label: 'Random Bytes Generation (32 bytes)',
        fn: async () => {
          const bytes = await randomBytes(32);
          // Should be base64 encoded - roughly 4/3 the size, so ~43 chars for 32 bytes
          const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
          const expectedLength = Math.ceil((32 * 4) / 3);
          const isValidBase64 = base64Regex.test(bytes);
          const isCorrectLength =
            bytes.length >= expectedLength - 2 &&
            bytes.length <= expectedLength + 2;

          if (isValidBase64 && isCorrectLength) {
            return `VALID BYTES (${bytes.length} chars)`;
          } else {
            return `INVALID: ${bytes} (length: ${bytes.length}, expected: ~${expectedLength})`;
          }
        },
        expected: 'VALID BYTES',
      },
      {
        key: 'random-bytes-small-test',
        label: 'Random Bytes Generation (8 bytes)',
        fn: async () => {
          const bytes = await randomBytes(8);
          // 8 bytes -> 12 base64 chars (with padding)
          const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
          return base64Regex.test(bytes) &&
            bytes.length >= 10 &&
            bytes.length <= 12
            ? `VALID (${bytes.length} chars)`
            : `INVALID: ${bytes}`;
        },
        expected: 'VALID',
      },
      {
        key: 'rsa-keygen-test',
        label: 'RSA Key Generation (2048-bit)',
        fn: async () => {
          const keyPair = await rsaGenerateKeys(2048);
          const hasPublic = keyPair.public.includes('BEGIN PUBLIC KEY');
          const hasPrivate = keyPair.private.includes('BEGIN PRIVATE KEY');
          return hasPublic && hasPrivate ? 'VALID KEYPAIR' : 'INVALID';
        },
        expected: 'VALID KEYPAIR',
      },
      {
        key: 'rsa-roundtrip-test',
        label: 'RSA Encrypt to Decrypt Roundtrip',
        fn: async () => {
          try {
            const keyPair = await rsaGenerateKeys(2048);
            const message = 'Hello RSA World!';

            const encrypted = await rsaEncrypt(message, keyPair.public);
            const decrypted = await rsaDecrypt(encrypted, keyPair.private);

            return decrypted === message ? 'PASS' : `FAIL: got "${decrypted}"`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'PASS',
      },
      {
        key: 'rsa-sign-verify-test',
        label: 'RSA Sign to Verify Roundtrip',
        fn: async () => {
          try {
            const keyPair = await rsaGenerateKeys(2048);
            const message = 'Hello RSA Signature!';

            const signature = await rsaSign(message, keyPair.private, 'SHA256');
            const verified = await rsaVerify(
              signature,
              message,
              keyPair.public,
              'SHA256'
            );

            return verified ? 'PASS' : 'FAIL: signature not verified';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'PASS',
      },
      {
        key: 'random-values-test',
        label: 'Random Alphanumeric Values (10 chars)',
        fn: async () => {
          const values = await getRandomValues(10);
          const alphanumericRegex = /^[A-Za-z0-9]{10}$/;
          return alphanumericRegex.test(values)
            ? `VALID: ${values}`
            : `INVALID: ${values}`;
        },
        expected: 'VALID:',
      },
      {
        key: 'rsa-jwk-export-test',
        label: 'RSA Export Key to JWK Format',
        fn: async () => {
          try {
            const keyPair = await rsaGenerateKeys(2048);
            const jwk = await rsaExportKey(keyPair.private);

            const hasRequiredProps =
              jwk.kty === 'RSA' &&
              jwk.n &&
              jwk.e &&
              jwk.d &&
              jwk.p &&
              jwk.q &&
              jwk.dp &&
              jwk.dq &&
              jwk.qi;

            return hasRequiredProps ? 'VALID JWK' : 'INVALID JWK';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'VALID JWK',
      },
      {
        key: 'rsa-jwk-import-test',
        label: 'RSA Import JWK to PEM Format',
        fn: async () => {
          try {
            // Generate a real RSA key pair first
            const keyPair = await rsaGenerateKeys(2048);

            // Export the public key to JWK format
            const publicJwk = await rsaExportKey(keyPair.public);

            // Remove private key components to make it a public-only JWK
            const publicOnlyJwk: JWK = {
              kty: publicJwk.kty,
              n: publicJwk.n,
              e: publicJwk.e,
            };

            // Now try to import the JWK back to PEM
            const pem = await rsaImportKey(publicOnlyJwk);
            const isValidPem =
              pem.includes('-----BEGIN RSA PUBLIC KEY-----') &&
              pem.includes('-----END RSA PUBLIC KEY-----');

            return isValidPem ? 'VALID PEM' : 'INVALID PEM';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'VALID PEM',
      },
      {
        key: 'rsa-jwk-roundtrip-test',
        label: 'RSA JWK to PEM to JWK Roundtrip',
        fn: async () => {
          try {
            const keyPair = await rsaGenerateKeys(2048);

            // Export PEM to JWK
            const originalJwk = await rsaExportKey(keyPair.private);

            // Import JWK to PEM
            const pemFromJwk = await rsaImportKey(originalJwk);

            // Export PEM back to JWK
            const roundtripJwk = await rsaExportKey(pemFromJwk);

            // Compare key properties (n should be the same)
            const isEqual =
              originalJwk.n === roundtripJwk.n &&
              originalJwk.e === roundtripJwk.e &&
              originalJwk.d === roundtripJwk.d;

            return isEqual ? 'ROUNDTRIP PASS' : 'ROUNDTRIP FAIL';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'ROUNDTRIP PASS',
      },
      {
        key: 'rsa-encrypt-pkcs1-test',
        label: 'RSA Encrypt with PKCS#1 Key (from JWK)',
        fn: async () => {
          try {
            // Generate a key pair and export to JWK
            const keyPair = await rsaGenerateKeys(2048);
            const publicJwk = await rsaExportKey(keyPair.public);

            // Import JWK to get PKCS#1 format key
            const pkcs1PublicKey = await rsaImportKey(publicJwk);

            // Verify it's PKCS#1 format (contains "RSA PUBLIC KEY")
            if (!pkcs1PublicKey.includes('RSA PUBLIC KEY')) {
              return 'ERROR: Expected PKCS#1 format key';
            }

            const message = 'Test PKCS#1 encryption!';

            // Test encryption with PKCS#1 key
            const encrypted = await rsaEncrypt(message, pkcs1PublicKey);

            // Decrypt with original private key to verify
            const decrypted = await rsaDecrypt(encrypted, keyPair.private);

            return decrypted === message
              ? 'PKCS#1 ENCRYPT OK'
              : `FAIL: got "${decrypted}"`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'PKCS#1 ENCRYPT OK',
      },
      {
        key: 'rsa-encrypt-x509-test',
        label: 'RSA Encrypt with X.509 Key (standard)',
        fn: async () => {
          try {
            // Generate standard X.509 key pair
            const keyPair = await rsaGenerateKeys(2048);

            // Verify it's X.509 format (contains "PUBLIC KEY")
            if (
              !keyPair.public.includes('PUBLIC KEY') ||
              keyPair.public.includes('RSA PUBLIC KEY')
            ) {
              return 'ERROR: Expected X.509 format key';
            }

            const message = 'Test X.509 encryption!';

            // Test encryption with X.509 key
            const encrypted = await rsaEncrypt(message, keyPair.public);
            const decrypted = await rsaDecrypt(encrypted, keyPair.private);

            return decrypted === message
              ? 'X.509 ENCRYPT OK'
              : `FAIL: got "${decrypted}"`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'X.509 ENCRYPT OK',
      },
    ];

    for (const test of tests) {
      try {
        setLoading((prev) => ({ ...prev, [test.key]: true }));
        const result = await test.fn();
        let isCorrect = false;

        if (test.key === 'aes-encrypt-test') {
          // For AES encrypt, just verify it's not null and not the original base64
          isCorrect =
            result !== 'null' &&
            result !== 'SGVsbG8gV29ybGQ=' &&
            result.length > 0;
        } else if (test.key === 'random-bytes-test') {
          // For random bytes, check if result starts with "VALID BYTES"
          isCorrect = result.startsWith('VALID BYTES');
        } else if (test.key === 'random-bytes-small-test') {
          // For small random bytes, check if result starts with "VALID"
          isCorrect = result.startsWith('VALID');
        } else if (test.key === 'random-values-test') {
          // For random values, check if result starts with "VALID:"
          isCorrect = result.startsWith('VALID:');
        } else {
          isCorrect = result.toLowerCase() === test.expected.toLowerCase();
        }

        setResults((prev) => ({
          ...prev,
          [test.key]: `${result} ${isCorrect ? '✓' : '✗'}`,
        }));
      } catch (error) {
        setResults((prev) => ({
          ...prev,
          [test.key]: `Error: ${error}`,
        }));
      } finally {
        setLoading((prev) => ({ ...prev, [test.key]: false }));
      }
    }
  };

  useEffect(() => {
    runCryptoTests();
  }, []);

  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.container}>
        <ScrollView
          style={styles.container}
          contentContainerStyle={styles.content}
        >
          <Text style={styles.title}>Mobile Crypto Test</Text>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>SHA Tests:</Text>

            <Text style={styles.testLabel}>SHA-256 UTF-8 ("hello"):</Text>
            <Text style={styles.result}>
              {loading['utf8-sha256']
                ? 'Loading...'
                : results['utf8-sha256'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>SHA-1 UTF-8 ("hello"):</Text>
            <Text style={styles.result}>
              {loading['utf8-sha1']
                ? 'Loading...'
                : results['utf8-sha1'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>SHA-256 Base64 ("aGVsbG8="):</Text>
            <Text style={styles.result}>
              {loading['base64-sha256']
                ? 'Loading...'
                : results['base64-sha256'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>SHA-512 UTF-8 ("test"):</Text>
            <Text style={styles.result}>
              {loading['utf8-sha512']
                ? 'Loading...'
                : results['utf8-sha512'] || 'Not run'}
            </Text>
          </View>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>PBKDF2 Tests:</Text>

            <Text style={styles.testLabel}>
              PBKDF2-SHA256 (pwd="password", salt="salt", iter=1000, len=32):
            </Text>
            <Text style={styles.result}>
              {loading['pbkdf2-sha256']
                ? 'Loading...'
                : results['pbkdf2-sha256'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              PBKDF2-SHA1 (pwd="password", salt="salt", iter=1000, len=20):
            </Text>
            <Text style={styles.result}>
              {loading['pbkdf2-sha1']
                ? 'Loading...'
                : results['pbkdf2-sha1'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              PBKDF2-SHA256 (pwd="password", salt="salt", iter=100000, len=32):
            </Text>
            <Text style={styles.result}>
              {loading['pbkdf2-sha256-100k']
                ? 'Loading...'
                : results['pbkdf2-sha256-100k'] || 'Not run'}
            </Text>
          </View>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>HMAC Tests:</Text>

            <Text style={styles.testLabel}>
              HMAC-SHA256 (data="Hello", key="key"):
            </Text>
            <Text style={styles.result}>
              {loading['hmac256-test1']
                ? 'Loading...'
                : results['hmac256-test1'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              HMAC-SHA256 (data="test", key="key"):
            </Text>
            <Text style={styles.result}>
              {loading['hmac256-test2']
                ? 'Loading...'
                : results['hmac256-test2'] || 'Not run'}
            </Text>
          </View>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>AES & Crypto Utils Tests:</Text>

            <Text style={styles.testLabel}>AES Encrypt (Hello World):</Text>
            <Text style={styles.result}>
              {loading['aes-encrypt-test']
                ? 'Loading...'
                : results['aes-encrypt-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              AES Encrypt to Decrypt Roundtrip:
            </Text>
            <Text style={styles.result}>
              {loading['aes-roundtrip-test']
                ? 'Loading...'
                : results['aes-roundtrip-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>Random UUID Generation:</Text>
            <Text style={styles.result}>
              {loading['random-uuid-test']
                ? 'Loading...'
                : results['random-uuid-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              Random Key Generation (16 bytes):
            </Text>
            <Text style={styles.result}>
              {loading['random-key-test']
                ? 'Loading...'
                : results['random-key-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              Random Bytes Generation (32 bytes):
            </Text>
            <Text style={styles.result}>
              {loading['random-bytes-test']
                ? 'Loading...'
                : results['random-bytes-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              Random Bytes Generation (8 bytes):
            </Text>
            <Text style={styles.result}>
              {loading['random-bytes-small-test']
                ? 'Loading...'
                : results['random-bytes-small-test'] || 'Not run'}
            </Text>
          </View>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              RSA & Advanced Crypto Tests:
            </Text>

            <Text style={styles.testLabel}>RSA Key Generation (2048-bit):</Text>
            <Text style={styles.result}>
              {loading['rsa-keygen-test']
                ? 'Loading...'
                : results['rsa-keygen-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA Encrypt to Decrypt Roundtrip:
            </Text>
            <Text style={styles.result}>
              {loading['rsa-roundtrip-test']
                ? 'Loading...'
                : results['rsa-roundtrip-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>RSA Sign to Verify Roundtrip:</Text>
            <Text style={styles.result}>
              {loading['rsa-sign-verify-test']
                ? 'Loading...'
                : results['rsa-sign-verify-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              Random Alphanumeric Values (10 chars):
            </Text>
            <Text style={styles.result}>
              {loading['random-values-test']
                ? 'Loading...'
                : results['random-values-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>RSA Export Key to JWK Format:</Text>
            <Text style={styles.result}>
              {loading['rsa-jwk-export-test']
                ? 'Loading...'
                : results['rsa-jwk-export-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>RSA Import JWK to PEM Format:</Text>
            <Text style={styles.result}>
              {loading['rsa-jwk-import-test']
                ? 'Loading...'
                : results['rsa-jwk-import-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>RSA JWK ↔ PEM Roundtrip Test:</Text>
            <Text style={styles.result}>
              {loading['rsa-jwk-roundtrip-test']
                ? 'Loading...'
                : results['rsa-jwk-roundtrip-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA Encrypt with PKCS#1 Key (from JWK):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-encrypt-pkcs1-test']
                ? 'Loading...'
                : results['rsa-encrypt-pkcs1-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA Encrypt with X.509 Key (standard):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-encrypt-x509-test']
                ? 'Loading...'
                : results['rsa-encrypt-x509-test'] || 'Not run'}
            </Text>
          </View>

          <Button title="Run Tests Again" onPress={runCryptoTests} />
        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  content: {
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 20,
  },
  section: {
    backgroundColor: 'white',
    padding: 15,
    marginBottom: 15,
    borderRadius: 8,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  testLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    marginTop: 10,
    marginBottom: 5,
  },
  result: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: '#333',
    backgroundColor: '#f8f8f8',
    padding: 8,
    borderRadius: 4,
  },
});
