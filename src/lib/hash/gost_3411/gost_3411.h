/*
* GOST 34.11
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_GOST_3411_H_
#define BOTAN_GOST_3411_H_

#include <botan/hash.h>
#include <botan/internal/gost_28147.h>

namespace Botan {

/**
* GOST 34.11
*/
class GOST_34_11 final : public HashFunction {
   public:
      std::string name() const override { return "GOST-R-34.11-94"; }

      size_t output_length() const override { return 32; }

      size_t hash_block_size() const override { return 32; }

      std::unique_ptr<HashFunction> new_object() const override { return std::make_unique<GOST_34_11>(); }

      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;

      GOST_34_11();

   private:
      void compress_n(const uint8_t input[], size_t blocks);

      void add_data(const uint8_t[], size_t) override;
      void final_result(uint8_t[]) override;

      GOST_28147_89 m_cipher;
      secure_vector<uint8_t> m_buffer, m_sum, m_hash;
      size_t m_position;
      uint64_t m_count;
};

}  // namespace Botan

#endif
