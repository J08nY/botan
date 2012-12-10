/*
* TLS Record Handling
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_RECORDS_H__
#define BOTAN_TLS_RECORDS_H__

#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
#include <vector>
#include <memory>
#include <chrono>

namespace Botan {

namespace TLS {

class Ciphersuite;
class Session_Keys;

class Connection_Sequence_Numbers;

/**
* TLS Cipher State
*/
class Connection_Cipher_State
   {
   public:
      /**
      * Initialize a new cipher state
      */
      Connection_Cipher_State(Protocol_Version version,
                              Connection_Side side,
                              const Ciphersuite& suite,
                              const Session_Keys& keys);

      BlockCipher* block_cipher() { return m_block_cipher.get(); }

      StreamCipher* stream_cipher() { return m_stream_cipher.get(); }

      MessageAuthenticationCode* mac() { return m_mac.get(); }

      secure_vector<byte>& cbc_state() { return m_block_cipher_cbc_state; }

      size_t block_size() const { return m_block_size; }

      size_t mac_size() const { return m_mac->output_length(); }

      size_t iv_size() const { return m_iv_size; }

      bool mac_includes_record_version() const { return !m_is_ssl3; }

      bool cipher_padding_single_byte() const { return m_is_ssl3; }

      bool cbc_without_explicit_iv() const
         { return (m_block_size > 0) && (m_iv_size == 0); }

      std::chrono::seconds age() const
         {
         return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - m_start_time);
         }

   private:
      std::chrono::system_clock::time_point m_start_time;
      std::unique_ptr<BlockCipher> m_block_cipher;
      secure_vector<byte> m_block_cipher_cbc_state;
      std::unique_ptr<StreamCipher> m_stream_cipher;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      size_t m_block_size = 0;
      size_t m_iv_size = 0;
      bool m_is_ssl3 = false;
   };

class Record
   {
   public:
      Record() {}

      Record(u64bit sequence,
             Protocol_Version version,
             Record_Type type,
             const byte contents[],
             size_t contents_size) :
         m_sequence(sequence),
         m_version(version),
         m_type(type),
         m_contents(contents, contents + contents_size) {}

      bool is_valid() const { return m_type != NO_RECORD; }

      u64bit sequence() const { return m_sequence; }

      Record_Type type() const { return m_type; }

      Protocol_Version version() const { return m_version; }

      const std::vector<byte>& contents() const { return m_contents; }

      const byte* bits() const { return &m_contents[0]; }

      size_t size() const { return m_contents.size(); }

   private:
      u64bit m_sequence = 0;
      Protocol_Version m_version = Protocol_Version();
      Record_Type m_type = NO_RECORD;
      std::vector<byte> m_contents;
   };

/**
* Create a TLS record
* @param write_buffer the output record is placed here
* @param msg_type is the type of the message (handshake, alert, ...)
* @param msg is the plaintext message
* @param msg_length is the length of msg
* @param msg_sequence_number is the sequence number
* @param version is the protocol version
* @param cipherstate is the writing cipher state
* @param rng is a random number generator
* @return number of bytes written to write_buffer
*/
void write_record(std::vector<byte>& write_buffer,
                  byte msg_type, const byte msg[], size_t msg_length,
                  Protocol_Version version,
                  Connection_Sequence_Numbers& sequence_numbers,
                  Connection_Cipher_State* cipherstate,
                  RandomNumberGenerator& rng);

/**
* Decode a TLS record
* @return zero if full message, else number of bytes still needed
*/
size_t read_record(std::vector<byte>& read_buffer,
                   const byte input[],
                   size_t input_length,
                   size_t& input_consumed,
                   Record& output_record,
                   Connection_Sequence_Numbers* sequence_numbers,
                   std::function<Connection_Cipher_State* (u16bit)> get_cipherstate);

}

}

#endif
