/*
* PKCS#11 ECC
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_P11_ECC_H_
#define BOTAN_P11_ECC_H_

#include <botan/p11_object.h>
#include <botan/pk_keys.h>

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
   #include <botan/asn1_obj.h>
   #include <botan/ec_group.h>
   #include <botan/ecc_key.h>
   #include <vector>

namespace Botan::PKCS11 {

class Session;

/// Properties for generating a PKCS#11 EC public key
class BOTAN_PUBLIC_API(2, 0) EC_PublicKeyGenerationProperties final : public PublicKeyProperties {
   public:
      /// @param ec_params DER-encoding of an ANSI X9.62 Parameters value
      EC_PublicKeyGenerationProperties(const std::vector<uint8_t>& ec_params);

      /// @return the DER-encoding of the ec parameters according to ANSI X9.62
      inline const std::vector<uint8_t>& ec_params() const { return m_ec_params; }

   private:
      const std::vector<uint8_t> m_ec_params;
};

/// Properties for importing a PKCS#11 EC public key
class BOTAN_PUBLIC_API(2, 0) EC_PublicKeyImportProperties final : public PublicKeyProperties {
   public:
      /**
      * @param ec_params DER-encoding of an ANSI X9.62 Parameters value
      * @param ec_point DER-encoding of ANSI X9.62 ECPoint value Q
      */
      EC_PublicKeyImportProperties(const std::vector<uint8_t>& ec_params, const std::vector<uint8_t>& ec_point);

      /// @return the DER-encoding of the ec parameters according to ANSI X9.62
      inline const std::vector<uint8_t>& ec_params() const { return m_ec_params; }

      /// @return the DER-encoding of the ec public point according to ANSI X9.62
      inline const std::vector<uint8_t>& ec_point() const { return m_ec_point; }

   private:
      const std::vector<uint8_t> m_ec_params;
      const std::vector<uint8_t> m_ec_point;
};

/// Represents a PKCS#11 EC public key
class BOTAN_PUBLIC_API(2, 0) PKCS11_EC_PublicKey : public virtual EC_PublicKey,
                                                   public Object {
   public:
      static const ObjectClass Class = ObjectClass::PublicKey;

      /**
      * Creates a PKCS11_EC_PublicKey object from an existing PKCS#11 EC public key
      * @param session the session to use
      * @param handle the handle of the ecc public key
      */
      PKCS11_EC_PublicKey(Session& session, ObjectHandle handle);

      /**
      * Imports an EC public key
      * @param session the session to use
      * @param props the attributes of the public key
      */
      PKCS11_EC_PublicKey(Session& session, const EC_PublicKeyImportProperties& props);
};

/// Properties for generating a PKCS#11 EC private key
class BOTAN_PUBLIC_API(2, 0) EC_PrivateKeyGenerationProperties final : public PrivateKeyProperties {
   public:
      EC_PrivateKeyGenerationProperties() : PrivateKeyProperties(KeyType::Ec) {}
};

/// Properties for importing a PKCS#11 EC private key
class BOTAN_PUBLIC_API(2, 0) EC_PrivateKeyImportProperties final : public PrivateKeyProperties {
   public:
      /**
      * @param ec_params DER-encoding of an ANSI X9.62 Parameters value
      * @param value ANSI X9.62 private value d
      */
      EC_PrivateKeyImportProperties(const std::vector<uint8_t>& ec_params, const BigInt& value);

      /// @return the DER-encoding of the ec parameters according to ANSI X9.62
      inline const std::vector<uint8_t>& ec_params() const { return m_ec_params; }

      /// @return the value of the ec private key
      inline const BigInt& value() const { return m_value; }

   private:
      const std::vector<uint8_t> m_ec_params;
      const BigInt m_value;
};

// note: don't inherit from PKCS11_EC_PublicKey: a private key object IS NOT A public key object on a smartcard (-> two different objects)
// note: don't inherit from EC_PublicKey: the public key can not be extracted from a PKCS11-EC-PrivateKey (its only attributes are CKA_EC_PARAMS and CKA_VALUE)
/// Represents a PKCS#11 EC private key
class BOTAN_PUBLIC_API(2, 0) PKCS11_EC_PrivateKey : public virtual Private_Key,
                                                    public Object {
   public:
      static const ObjectClass Class = ObjectClass::PrivateKey;

      /**
      * Creates a PKCS11_EC_PrivateKey object from an existing PKCS#11 EC private key
      * @param session the session to use
      * @param handle the handle of the EC private key
      */
      PKCS11_EC_PrivateKey(Session& session, ObjectHandle handle);

      /**
      * Imports an EC private key
      * @param session the session to use
      * @param props the attributes of the private key
      */
      PKCS11_EC_PrivateKey(Session& session, const EC_PrivateKeyImportProperties& props);

      /**
      * Generates a PKCS#11 EC private key
      * @param session the session to use
      * @param ec_params DER-encoding of an ANSI X9.62 Parameters value
      * @param props the attributes of the private key
      * @note no persistent public key object will be created
      */
      PKCS11_EC_PrivateKey(Session& session,
                           const std::vector<uint8_t>& ec_params,
                           const EC_PrivateKeyGenerationProperties& props);

      /// @returns the domain of the EC private key
      inline const EC_Group& domain() const { return m_domain_params; }

      /**
      * Set the point encoding method to be used when encoding this key.
      * @param enc the encoding to use
      */
      void set_point_encoding(EC_Point_Format enc);

      /**
      * Return the DER encoding of this keys domain in whatever format
      * is preset for this particular key
      */
      std::vector<uint8_t> DER_domain() const {
        return domain().DER_encode(domain_format());
      }

      /**
      * Get the domain parameter encoding to be used when encoding this key.
      * @result the encoding to use
      */
      EC_Group_Encoding domain_format() const { return m_domain_encoding; }

      /**
      * Get the point encoding method to be used when encoding this key.
      * @result the encoding to use
      */
      EC_Point_Format point_encoding() const { return m_point_encoding; }

      /**
      * Set the domain parameter encoding to be used when encoding this key.
      * @param enc the encoding to use
      */
      void set_parameter_encoding(EC_Group_Encoding enc);

      /**
      * Sets the associated public point of this private key
      * @param point the public point
      * @param enc encoding of the point (default DER-encoded)
      */
      void set_public_point(const EC_Point& point, PublicPointEncoding enc = PublicPointEncoding::Der) {
         m_public_key = point;
         m_point_encoding = enc;
      }

      /**
       * Sets the public desired public point encoding of this private key, when it is passed to cryptoki functions.
       * This could be either `PublicPointEncoding::Raw` or `PublicPointEncoding::Der`. By default this is set to `Der`,
       * but some tokens might expect `Raw`-encoded public keys, e.g. when using this private key for key agreement.
       */
      void set_public_point_encoding(PublicPointEncoding enc) { m_public_point_encoding = enc; }

      /**
      * Gets the public_point
      * @note the public key must be set using `set_public_point`
      *       because it is not possible to infer the public key from a PKCS#11 EC private key
      * @return the public point of the private key
      * @throws Exception if the public point was not set using set_public_point()
      */
      const EC_Point& public_point() const {
         if(m_public_key.is_zero()) {
            throw Invalid_State(
               "Public point not set. Inferring the public key from a PKCS#11 ec private key is not possible.");
         }
         return m_public_key;
      }

      /// @return the encoding format for the public point when it is passed to cryptoki functions as an argument
      PublicPointEncoding public_point_encoding() const { return m_public_point_encoding; }

      // Private_Key methods

      std::vector<uint8_t> public_key_bits() const override;

      std::size_t key_length() const override;

      std::size_t estimated_strength() const override;

      bool check_key(RandomNumberGenerator&, bool) const override;

      AlgorithmIdentifier algorithm_identifier() const override;

   private:
      EC_Group m_domain_params;
      EC_Point m_public_key;
      PublicPointEncoding m_public_point_encoding{PublicPointEncoding::Der};
      EC_Point_Format m_point_encoding{EC_Point_Format::Uncompressed};
      EC_Group_Encoding m_domain_encoding{EC_Group_Encoding::Explicit};
};
}  // namespace Botan::PKCS11

#endif

#endif
